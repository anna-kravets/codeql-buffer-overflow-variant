# How `UnboundedCopyToFixedBuffer.ql` works

Running it: see [`README.md`](README.md). This file explains what it decides and why.

## The bug class

> A `memcpy`-family call writes into a **fixed-size stack buffer** using a length that is
> **never compared against that buffer's size**.

CWE-120 / CWE-121 / CWE-787. Instance: **CVE-2020-8597**, pppd's EAP `rhostname` overflow
(CVSS 3.1 9.8). Course anchor: `lectures/12. Static Analysis.md` (sinks, guards, variant
analysis) and `lectures/5. Buffer Overflow Attack.md` (why a 256-byte stack array matters).

## Three conditions

A call is reported when all three hold.

**1. Sink shape — `copiesIntoFixedBuffer`**
The call targets `memcpy`, `memmove`, `strncpy` or their `__builtin*` / FORTIFY `_chk`
spellings, and argument 0 mentions a local array of statically known size. `bcopy` is
excluded on purpose: its destination is argument 1. pppd's `BCOPY(s, d, l)` macro expands to
`memcpy(d, s, l)` (`pppd/pppd.h:816`), so the database already holds a plain `memcpy` in
`(dest, src, len)` order.

**2. Length is not a safe constant — `constantLength`**
A compile-time constant length that fits the destination is safe by construction and is
dropped. This removes pppd's trimming branch at `eap.c:1425`, `BCOPY(..., sizeof (rhostname) - 1)`.

**3. No guard on the length — `lengthCheckedAgainstDestSize`**
No comparison anywhere in the enclosing function satisfies **both** of:

- one operand has the same **global value number** as the copy's length expression, and
- the other operand **is** `sizeof(dest)` or the array's literal size — not merely contains it.

If no such comparison exists, the copy is unguarded and the call is reported.

## Why condition 3 is the whole query

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

## How each target lands

| Site | Check present? | Which half fails | Verdict |
| ---- | -------------- | ---------------- | ------- |
| `eap.c:1428` `rhostname` (vuln) | yes, dead | both — wrong value **and** wrong bound | **reported** — the CVE |
| `eap.c:1854` `rhostname` (vuln) | yes, dead | both | **reported** — same bug, different call path |
| `eap.c` `rhostname` (patched) | yes, live | neither | silent |
| `tlv_server.c:78` `name` | yes, `vlen > plen - 2` | bound only — `plen - 2` is the frame size, not `sizeof(name)` | **reported** |
| `tlv_server.c:104` `buf` | yes, `vlen >= sizeof(buf)` | neither | silent |

Note the split: pppd fails on the **value-number** half, `handle_hello` fails on the **bound**
half. Two distinct ways to get the same bug class, one predicate catching both — that is the
variant analysis the assignment asks for.

## What it deliberately does not do

This is the crude first version (Phase 2, step 1). No taint tracking, so an unguarded length
is flagged whether or not it is attacker-derived; no source modelling, so nothing yet depends
on whether taint crosses pppd's `protent.input` table or the variant's `ops[].handle` table;
guard scope is the whole function rather than control-flow dominance; stack buffers only;
copy-family calls only, so pppd's one-byte `rhostname[len - vallen] = '\0'` at `eap.c:1429` is
a second out-of-bounds write that goes unmatched. Full list and next steps in
[`README.md`](README.md#limitations-of-this-basic-version-and-what-comes-next).
