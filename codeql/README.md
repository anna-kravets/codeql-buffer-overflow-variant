# Part 3 CodeQL query — running it from the VM

`UnboundedCopyToFixedBuffer.ql` is the **basic (Phase 2, step 1)** version of the Part 3
query for **CVE-2020-8597** — the pppd EAP `rhostname` stack buffer overflow. It is
sink-centric: no taint tracking yet, no source modelling, no function-pointer bridging.
Those are the next steps (see *Limitations* below).

For what the query decides and why, see [`query-explained.md`](query-explained.md).

> **Run everything below inside the course VM.** Building a CodeQL database means running
> the target's real build (`make`), which is what the "VM only" rule is about. Query
> execution itself never runs the analysed code — it only reads the database — but keeping
> the CLI, the query pack and both databases on one machine avoids the CodeQL
> version-mismatch trap and keeps the demo reproducible.

## What the query looks for

> A `memcpy`-family call whose destination is a fixed-size stack buffer and whose length
> operand is never compared against that buffer's size.

Three conditions, all in `UnboundedCopyToFixedBuffer.ql`:

1. **Sink shape** — `memcpy` / `memmove` / `strncpy` (plus the `__builtin*` and FORTIFY
   `_chk` spellings) writing into a local array of known size. pppd's `BCOPY(s, d, l)`
   macro expands to `memcpy(d, s, l)`, so the database records a plain `memcpy` with the
   arguments already in `(dest, src, len)` order.
2. **Length is not a safe constant** — drops `BCOPY(..., sizeof (rhostname) - 1)` in the
   dead trimming branch (`eap.c:1425`), which is safe by construction.
3. **No guard on the length** — no comparison in the function bounds *the copy length
   expression itself* against `sizeof(dest)` or the array's literal size.

Condition 3 is the whole point. pppd **does** have a bounds check —
`if (vallen >= len + sizeof (rhostname))` at `eap.c:1423` — and a naive "is there a check
mentioning `sizeof(dest)`?" query is silenced by it. This query compares *value numbers*:
the check bounds `vallen`, the copy length is `len - vallen`, different value → not a
guard → still reported. The patch changes the comparison to `len - vallen >= sizeof
(rhostname)`, which **is** the copy length → guard recognised → patched tree goes quiet.
One predicate, both verdicts.

## Prerequisites

CodeQL CLI bundle installed per `sp-final-project/part 3/vm-setup.md` §4, and the two pppd
databases from §5 and §6. Assumed layout on the VM:

```
~/part3/ppp-vuln/db                          # ppp-2.4.8   (vulnerable)
~/part3/ppp-fixed/db                         # 8d7970b8    (patched, negative control)
~/part3/codeql-buffer-overflow-variant/      # this repo
```

Get this repo onto the VM (or use a shared folder):

```bash
cd ~/part3
git clone <this-repo-url> codeql-buffer-overflow-variant
```

## 1. Build the variant database

```bash
cd ~/part3/codeql-buffer-overflow-variant
make clean
codeql database create db --language=cpp --command="make"
```

**Verify:** `Successfully created database at ...db`. (`db/` is already gitignored.)

## 2. Compile the query first

Cheapest possible check that every predicate and import name exists in *your* bundle —
seconds, no database needed. Run this after every edit, before running.

```bash
codeql query compile ~/part3/codeql-buffer-overflow-variant/codeql/UnboundedCopyToFixedBuffer.ql
```

If it fails on `codeql/cpp-all` resolution, point the CLI at the bundle explicitly:

```bash
codeql query compile --search-path ~/codeql <query.ql>
```

If it fails on `globalValueNumber`, the equivalent library in your bundle is
`semmle.code.cpp.valuenumbering.HashCons` — swap the import and use `hashCons(...)` in
`lengthCheckedAgainstDestSize`. Both ship with the C/C++ pack; which one is present
depends on the bundle version, and `query compile` is what settles it.

## 3. Run it

```bash
Q=~/part3/codeql-buffer-overflow-variant/codeql/UnboundedCopyToFixedBuffer.ql

codeql query run "$Q" --database=$HOME/part3/ppp-vuln/db   --threads=0   # the CVE
codeql query run "$Q" --database=$HOME/part3/ppp-fixed/db  --threads=0   # negative control
codeql query run "$Q" --database=$HOME/part3/codeql-buffer-overflow-variant/db --threads=0
```

For results that go into the write-up (stable, quotable, countable), use `analyze` instead
— the query carries `@id` and `@kind` metadata, so both CSV and SARIF work:

```bash
codeql database analyze $HOME/part3/ppp-vuln/db "$Q" \
    --format=csv --output=results-ppp-vuln.csv
```

## 4. Expected results

Measured on the VM (CodeQL bundle in `~/codeql`, evaluation 30 s per pppd database, 7 s for
the variant):

| Database | Hits | Detail |
| -------- | ---- | ------ |
| `ppp-vuln` (2.4.8) | 4 | `eap.c:1428` in `eap_request()` — **the CVE**; `eap.c:1854` in `eap_response()` — free variant analysis, same bug, different call path; plus `temp` (1024 B, length `minlen`) and `passbuf` (48 B, length `length`) |
| `ppp-fixed` (`8d7970b8`) | 2 | **both `rhostname` hits gone**; `temp` and `passbuf` remain |
| variant (`tlv_server.c`) | 1 | `tlv_server.c:78` in `handle_hello()`; **no hit** at `tlv_server.c:104` in `handle_echo()`, which bounds `vlen` against `sizeof(buf)` |

The vuln-minus-fixed difference is the result: patch `8d7970b8` touches only `eap.c`, and
only the `eap.c` findings disappear. No query edits between the two runs.

`temp`/`minlen` and `passbuf`/`length` survive the patch, so they are not the CVE. They are
untriaged — the basic query has no source modelling, so hits on lengths that are not
attacker-derived are expected. Triage them from the `analyze` CSV (locations are also in the
`query run` message since the query prints `file:line in function()`); taint tracking is the
Phase 2 step that should drop them if they are false positives.

## Limitations of this basic version (and what comes next)

Deliberate — this is the crude first version the Phase 2 plan calls for. Each line below is
a step in `sp-final-project/part 3/plan.md` §Phase 2:

- **No taint tracking.** Any unguarded length flags, whether or not it is attacker-derived.
  Next: `TaintTracking::Global<...>` from remote sources (`read`/`recvfrom`) to the length
  argument.
- **No source modelling**, therefore nothing yet depends on whether CodeQL's default taint
  model crosses the indirect call through pppd's `protent.input` table (`main.c:1092`) or
  the variant's `ops[i].handle` table (`tlv_server.c:120`). That is the flagged unknown, and
  it only bites once taint is added.
- **Guard scope is the whole function**, not "guard control-flow-dominates the sink". Sound
  enough for both targets; tighten with `GuardCondition.controls(...)` if Phase 4 turns up
  a false negative.
- **Stack buffers only** (`LocalVariable`). Globals and heap allocations are out of scope.
- **Byte-element arrays assumed** — `destSize` is the array's size in bytes, compared
  directly against a `memcpy` length. True for `char[]` in both targets.
- **Copy-family calls only.** pppd's one-byte NUL write `rhostname[len - vallen] = '\0'`
  (`eap.c:1429`) is a second out-of-bounds write and is not matched.
