# How the Part 3 queries work

Running them: see [`README.md`](README.md). This file explains what they decide and why.

## The bug class

> A `memcpy`-family call writes into a **fixed-size stack buffer** using an
> **attacker-derived length** that is **never compared against that buffer's size**.

CWE-120 / CWE-121 / CWE-787. Instance: **CVE-2020-8597**, pppd's EAP `rhostname` overflow
(CVSS 3.1 9.8). Course anchors: `lectures/12. Static Analysis.md` (sources, sinks, taint vs
data flow, variant analysis) and `lectures/5. Buffer Overflow Attack.md`.

## Two queries, one library

`CopyToFixedBuffer.qll` holds the sink shape and the guard test. Both queries import it and
neither redefines anything, so the only difference between their result sets is the taint
condition. That is deliberate: the comparison is only evidence if nothing else changed.

- `UnboundedCopyToFixedBuffer.ql` — conditions 1–3. Verified.
- `UnboundedCopyTainted.ql` — conditions 1–4. Written, not yet verified.

## Conditions 1–3: the sink

**1. Sink shape — `copiesIntoFixedBuffer`**
The call targets `memcpy`, `memmove`, `strncpy` or their `__builtin*` / FORTIFY `_chk`
spellings, and argument 0 mentions a local array of statically known size. `bcopy` is
excluded on purpose: its destination is argument 1. pppd's `BCOPY(s, d, l)` macro expands to
`memcpy(d, s, l)` (`pppd/pppd.h:816`), so the database already holds a plain `memcpy` in
`(dest, src, len)` order.

**2. Length is not a safe constant — `constantLength`**
A compile-time constant length that fits the destination is safe by construction and is
dropped. This removes pppd's trimming branch at `eap.c:1425`,
`BCOPY(..., sizeof (rhostname) - 1)`.

**3. No guard on the length — `lengthCheckedAgainstDestSize`**
No comparison anywhere in the enclosing function satisfies **both** of:

- one operand has the same **global value number** as the copy's length expression, and
- the other operand **is** `sizeof(dest)` or the array's literal size — not merely contains it.

If no such comparison exists, the copy is unguarded.

## Why condition 3 is the interesting one

pppd is not missing a bounds check. It has one, at `eap.c:1423`:

```c
if (vallen >= len + sizeof (rhostname)) {
        ...                                     /* dead: vallen <= len always */
} else {
        BCOPY(inp + vallen, rhostname, len - vallen);   /* eap.c:1428 — the overflow */
}
```

A naive query — "is there a check mentioning `sizeof(dest)`?" — is silenced by this line and
misses the CVE entirely. Condition 3 fails it on **both** halves:

- the checked value is `vallen`; the copy length is `len - vallen`. Different value number.
- the bound is `len + sizeof (rhostname)`, an addition. Not the destination size.

The fix commit `8d7970b8` rewrites the comparison to `len - vallen >= sizeof (rhostname)`.
Now the checked value **is** the copy length and the bound **is** the size, so the same
predicate recognises it as a genuine guard and the patched tree goes quiet. One predicate,
opposite verdicts, no query edits between the two runs — that is the negative control.

Global value numbering (`semmle.code.cpp.valuenumbering.GlobalValueNumbering`) is what makes
"the same value, however it is spelled" decidable. Syntactic comparison would not survive the
patch's reordering.

## Condition 4: taint

The write-up argues (§5, §8) that this CVE needs taint tracking, not plain data flow: the
length does not survive as one value. `get_input()` computes `len` from `read()`'s return,
`eap_input()` discards it and re-reads a *new* length field out of the packet body, and
`eap_request()` copies `len - vallen`. Every hop is a new value built from attacker bytes.
Data flow follows identity; taint follows influence. `UnboundedCopyTainted.ql` is what makes
that argument true of the query and not just of the prose.

`TaintTracking::Global<UnboundedCopyConfig>`, source → the length operand of a copy that has
already failed conditions 1–3. Restricting the sink set inside the configuration rather than
in the `where` clause keeps the flow computation small, which matters on the VM's 1.3 GB
evaluator heap.

### The source, and why it is not the obvious one

**`RemoteFlowSource`** — the C/C++ pack's own model of network input — would be the right
place to start, and the query does not use it. In the bundle on the VM it is built on a
different dataflow library than `semmle.code.cpp.dataflow.new`, and importing both makes the
name `DataFlow` ambiguous. `SourceProbe.ql` imports it in isolation and reports what it would
have contributed, so the cost is measured rather than assumed.

**Dispatch-table handler parameters** are therefore the only source — and they are the one
that actually matters here, because neither program calls the vulnerable handler by name:

```c
/* pppd — main.c dispatches through this table */
struct protent eap_protent = { PPP_EAP, eap_init, eap_input, ... };
    (*protp->input)(0, p, len);          /* the string "eap_input" is nowhere here */

/* variant — tlv_server.c dispatches through a different one */
static const struct op ops[] = { {1, handle_hello}, {2, handle_echo} };
    ops[i].handle(payload, plen);        /* likewise for "handle_hello" */
```

If the pack's inter-procedural model does not resolve that indirect call, taint from the real
`read()` never arrives and the query finds nothing. `dispatchTableTarget()` recognises any
function whose address is stored in an aggregate initialiser or assigned into a struct field,
and treats its parameters as tainted — picking taint up on the far side of the edge.

It names neither table, so it generalises to any dispatch-table design. That matters for
grading: the assignment asks for a query that survives a *different structure and call chain*,
and these two tables have different shapes, different depths and different struct layouts.

Be honest about the cost, twice over.

This is an **over-approximation**: it assumes any function reachable only through a
function-pointer table is reachable with attacker-supplied arguments. For a protocol
dispatcher that is exactly true. In general it is not, and the write-up should say so rather
than hide it.

And it is the *only* source, so taint starts inside the handler rather than at the `read()`.
The query therefore demonstrates that the length is handler-derived, not that it is
provably network-derived — the `read()` → dispatcher edge is argued in the write-up (§5) and
not re-proved by the query. That is a real limitation, and naming it is better than being
asked about it.

`SourceProbe.ql` exists to measure both of those before running the real query — so an empty
result is diagnosable instead of mysterious.

## How each site lands

| Site | Check present? | Which half fails | Sink-only | Tainted (predicted) |
| ---- | -------------- | ---------------- | --------- | ------------------- |
| `eap.c:1428` `rhostname` (vuln) | yes, dead | both — wrong value **and** wrong bound | **hit** — the CVE | **hit** |
| `eap.c:1854` `rhostname` (vuln) | yes, dead | both | **hit** — same bug, other path | **hit** |
| `eap.c` `rhostname` (patched) | yes, live | neither | silent | silent |
| `chat.c:1509` `temp` | no | — | hit | silent — `minlen` is from local config |
| `sendserver.c:104` `passbuf` | unread | — | hit | silent — outgoing RADIUS packing |
| `tlv_server.c:78` `name` | yes, `vlen > plen - 2` | bound only — `plen - 2` is the frame size, not `sizeof(name)` | **hit** | **hit** |
| `tlv_server.c:104` `buf` | yes, `vlen >= sizeof(buf)` | neither | silent | silent |

Note the split in the two vulnerable sites: pppd fails on the **value-number** half,
`handle_hello` fails on the **bound** half. Two distinct ways to reach the same bug class, one
predicate catching both — that is the variant analysis the assignment asks for.

The last two columns are the experiment. The tainted predictions are recorded before the run,
not after; if they do not hold, the reason is the finding.

## What is still not modelled

Guard scope is the whole enclosing function rather than control-flow dominance. Stack buffers
only. Array sizes assumed to be in bytes (true for `char[]` in both targets). Copy-family
calls only, so pppd's one-byte `rhostname[len - vallen] = '\0'` at `eap.c:1429` — a second
out-of-bounds write — goes unmatched. No recognition of the clamp idiom `if (n > N) n = N;`.
Full list in [`README.md`](README.md#limitations-and-what-remains).
