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

- `UnboundedCopyToFixedBuffer.ql` — conditions 1–3. Verified: 4 / 2 / 2.
- `UnboundedCopyTainted.ql` — conditions 1–4. Verified: 2 / 0 / 2.

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

### Which half does the work, and where

Worth being precise, because the two halves are not interchangeable and it is a fair question
to be asked.

**The bound half** — "the operand must *be* `sizeof(dest)`, not merely contain it" — is what
decides pppd. `len + sizeof (rhostname)` is an addition, so it is rejected, and the patched
form `sizeof (rhostname)` is accepted. Value numbering agrees with both verdicts but does not
change either: strike it out and pppd's results are identical.

**The value half** — global value numbering
(`semmle.code.cpp.valuenumbering.GlobalValueNumbering`) — earns its place on a different
shape, where a comparison *does* name the destination size but constrains the wrong variable.
`handle_stat` in the variant is exactly that:

```c
if (hlen >= sizeof(report))            /* names the buffer, bounds the WRONG length */
        return;
...
memcpy(report, payload + 2, blen);     /* the copy length is blen, not hlen */
```

Without value numbering, `sizeof(report)` satisfies the bound half and the copy is treated as
guarded — a false negative. With it, `globalValueNumber(hlen) != globalValueNumber(blen)`, so
the comparison is not accepted and the bug is reported.

That is the informal description everyone gives of CVE-2020-8597 — *"a check that mentions the
buffer size while constraining something that isn't the copy length"* — reproduced as a
minimal, isolated case. pppd's own expression happens to fail the bound half as well, so it
does not test this on its own.

Value numbering also makes "the same value, however it is spelled" decidable, which is why the
guard test survives the patch reordering its operands rather than depending on syntax.

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

The path CodeQL produced on pppd is the argument made mechanically. Its 39 nodes read
`inp` → `*inp` → `... ++` → `... = ...` → `... -= ...` → `len` → `... - ...`: the pointer
walks forward through the packet, the length is reassigned and decremented, and the final
node is the copy length. No single value survives from the parameter to the sink, which is
exactly why data flow is not enough. The same query on the variant produces a 4-node path,
`payload` → the byte-combining expression → `vlen` — forty times shorter, same verdict.

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

| Site | Check present? | Which half fails | Sink-only | Tainted |
| ---- | -------------- | ---------------- | --------- | ------- |
| `eap.c:1428` `rhostname` (vuln) | yes, dead | both — wrong value **and** wrong bound | **hit** — the CVE | **hit** |
| `eap.c:1854` `rhostname` (vuln) | yes, dead | both | **hit** — same bug, other path | **hit** |
| `eap.c` `rhostname` (patched) | yes, live | neither | silent | silent |
| `chat.c:1509` `temp` | no | — | hit | **silent** — length is from local config, not the network |
| `sendserver.c:104` `passbuf` | not read | — | hit | **silent** — outgoing RADIUS packing |
| `tlv_server.c:80` `name` | yes, `vlen > plen - 2` | **bound only** — `plen - 2` is the frame, not `sizeof(name)` | **hit** | **hit** |
| `tlv_server.c:106` `buf` | yes, `vlen >= sizeof(buf)` | neither | silent | silent |
| `tlv_server.c:145` `report` | yes, `hlen >= sizeof(report)` | **value only** — names the buffer, bounds the wrong length | **hit** | **hit** |

The three vulnerable sites cover the space between them. pppd fails both halves;
`handle_hello` fails only the bound half; `handle_stat` fails only the value half. One
predicate, three shapes, and each half of it is load-bearing somewhere — that is the variant
analysis the assignment asks for, and it is also the answer to "why is that complexity in the
query?"

Taint results were predicted before each run — 2 / 0 / 1 before `handle_stat` existed, then
2 / 0 / 2 after it was added — and came out exactly that both times. Taint crossed both
function-pointer tables, which was the largest open risk in the plan. The two non-CVE pppd
rows went silent, so they were source-scope, not precision, problems: precision on the
vulnerable tree is 2 of 2, and the patched tree returns nothing at all.

`handle_stat` fired, which is what the value half of condition 3 exists for. That was then
checked by ablation — value numbering commented out, nothing else changed:

| Database | Sink-only | Tainted |
| -------- | --------- | ------- |
| `ppp-vuln` | 4 → **3** | 2 → **2** |
| `ppp-fixed` | 2 → **1** | 0 → **0** |
| variant | 2 → **1** | 2 → **1** |

Two findings disappear and they differ in kind. `tlv_server.c:145` is a **true positive lost** —
the case value numbering exists for. `chat.c:1509` is a **false positive lost**, shed by
accident: the weak query accepts `len > STR_LEN` because `STR_LEN` is the literal 1024, without
caring that it bounds `len` while the copy length is `minlen`. Reading `chat.c` confirms the
copy is genuinely safe, via a bound the query cannot follow — it constrains a *predecessor* of
the copy length, which needs range analysis rather than value equality.

So removing value numbering is a trade on the sink-only query (one true positive for one false
positive) and a **pure loss** on the tainted one, where `chat.c` never appears. See
[`README.md`](README.md) for the full note.

The variant's `nodes` table also shows the two handlers reached by *different expression
shapes*: `handle_stat` through `payload` → *access to array* → `blen` (the single subscript
`payload[1]`), `handle_hello` through `payload` → `... | ...` → `vlen` (the shift-and-or). One
source, one sink kind, two idioms, both followed.

Each finding appears as two rows, sourced from `inp` and `*inp` (pppd) or `payload` and
`*payload` (variant). `asParameter(_)` matches the parameter at every indirection level, so
taint arrives both as the pointer and through its pointee — two real paths, one sink. Count
findings, not rows.

## What is still not modelled

Guard scope is the whole enclosing function rather than control-flow dominance. Stack buffers
only. Array sizes assumed to be in bytes (true for `char[]` in both targets). Copy-family
calls only, so pppd's one-byte `rhostname[len - vallen] = '\0'` at `eap.c:1429` — a second
out-of-bounds write — goes unmatched. No recognition of the clamp idiom `if (n > N) n = N;`.
Full list in [`README.md`](README.md#limitations-and-what-remains).
