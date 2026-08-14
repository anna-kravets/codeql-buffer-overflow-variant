# Part 3 CodeQL queries — running them from the VM

Queries for **CVE-2020-8597**, the pppd EAP `rhostname` stack buffer overflow.

| File | What it is |
| ---- | ---------- |
| `CopyToFixedBuffer.qll` | Shared library: the sink shape and the guard test. Both queries import it, so the only difference between their results is taint. |
| `UnboundedCopyToFixedBuffer.ql` | **Phase 2 step 1** — sink shape only, no taint. Verified: 4 / 2 / 2. |
| `UnboundedCopyTainted.ql` | **Phase 2 steps 2–4** — same sink, plus the length must be attacker-derived. Verified: 2 / 0 / 2. |
| `SourceProbe.ql` | Diagnostic. Run it if the taint query returns nothing. |

For what the queries decide and why, see [`query-explained.md`](query-explained.md).

> **Run everything below inside the course VM.** Building a CodeQL database means running
> the target's real build (`make`), which is what the "VM only" rule is about. Query
> execution itself never runs the analysed code — it only reads the database — but keeping
> the CLI, the query pack and all three databases on one machine avoids the CodeQL
> version-mismatch trap and keeps the demo reproducible.

## What the queries look for

> A `memcpy`-family call whose destination is a fixed-size stack buffer and whose length
> operand is never compared against that buffer's size — and, in the tainted version, is
> derived from attacker input.

Three sink-side conditions, all in `CopyToFixedBuffer.qll`:

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
mentioning `sizeof(dest)`?" query is silenced by it. The query compares *value numbers*:
the check bounds `vallen`, the copy length is `len - vallen`, different value → not a
guard → still reported. The patch changes the comparison to `len - vallen >= sizeof
(rhostname)`, which **is** the copy length → guard recognised → patched tree goes quiet.
One predicate, both verdicts.

`UnboundedCopyTainted.ql` adds a fourth condition: taint must reach the length operand from
the parameters of a dispatch-table handler. `RemoteFlowSource` would be the better source
and is not used — in this bundle it cannot be imported alongside `dataflow.new` without
making the name `DataFlow` ambiguous. `SourceProbe.ql` reports what it would have
contributed. See [`query-explained.md`](query-explained.md) for why dispatch-table
parameters are the source that actually matters here.

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

Redo this **every time `tlv_server.c` changes** — `database create` snapshots the source, so
an existing `db/` will not see new code.

```bash
cd ~/part3/codeql-buffer-overflow-variant
rm -rf db
make clean
codeql database create db --language=cpp --command="make"
```

**Verify:** `Successfully created database at ...db`. (`db/` is already gitignored.)

## 2. Compile before running

Cheapest possible check that every predicate and import name exists in *your* bundle —
seconds, no database needed. Run this after every edit.

```bash
cd ~/part3/codeql-buffer-overflow-variant/codeql
codeql query compile UnboundedCopyToFixedBuffer.ql UnboundedCopyTainted.ql SourceProbe.ql
```

If it fails on `codeql/cpp-all` resolution, point the CLI at the bundle explicitly with
`--search-path ~/codeql`.

**Fallback ladder if the taint query does not compile.** These names are newer than the
rest and vary by bundle version; the sink-only query is unaffected either way.

| Error mentions | Try instead |
| -------------- | ----------- |
| `could not resolve module ...dataflow...` | list what your bundle actually ships and read the module name off the path: `find ~/codeql ~/.codeql -path '*cpp*' \( -name 'DataFlow.qll' -o -name 'TaintTracking.qll' \) 2>/dev/null` — everything from `semmle/` onward, with `/` replaced by `.`, is the import |
| `DataFlow::ConfigSig` or `TaintTracking::Global` | pre-2023 bundle: replace the module with `class Cfg extends TaintTracking::Configuration` and `isSource` / `isSink` member predicates, and use `Cfg.hasFlowPath(source, sink)` |
| `asParameter(_)` | drop the argument: `source.asParameter() = handler.getAParameter()` — scalar parameters only, which is enough for the variant but **not** for pppd, whose length is re-read from the packet body |
| `module DataFlow is ambiguous` | two imports supply different modules of the same name. **Already hit and resolved**: `FlowSources` is no longer imported by the taint query, only by `SourceProbe.ql`, which needs no other dataflow library |
| `globalValueNumber` | import `semmle.code.cpp.valuenumbering.HashCons`, use `hashCons(...)` |

**Resolved so far on the VM's bundle:** `GlobalValueNumbering` / `globalValueNumber`,
`ArrayType.getSize()` (returns bytes), `semmle.code.cpp.security.FlowSources`. The `new`
dataflow library is at `semmle.code.cpp.dataflow.new.*`, **not** `semmle.code.cpp.ir.dataflow.new.*`
— the `new` directory sits under `dataflow/`, not under `ir/dataflow/`.

## 3. Probe the sources first

```bash
Q=~/part3/codeql-buffer-overflow-variant/codeql
codeql query run "$Q/SourceProbe.ql" --database=$HOME/part3/ppp-vuln/db --threads=0
```

Two things to read off the result:

- **Does any `RemoteFlowSource` appear at all**, and in particular in `read_packet()`
  (`sys-linux.c`)? If not, the pack does not model pppd's PPP `read()` as remote input and
  the taint query is relying entirely on the dispatch-table sources.
- **Is `eap_input` listed as a dispatch-table handler?** It must be — pppd registers it in
  `struct protent eap_protent`. If it is missing, `dispatchTableTarget()` is not matching
  pppd's initialiser shape and needs widening before the taint query can work.

Run the same probe on the variant DB; `handle_hello` and `handle_echo` should both appear.

## 4. Run the queries

```bash
Q=~/part3/codeql-buffer-overflow-variant/codeql

for db in ppp-vuln ppp-fixed codeql-buffer-overflow-variant; do
  echo "=== $db ==="
  codeql query run "$Q/UnboundedCopyToFixedBuffer.ql" --database=$HOME/part3/$db/db --threads=0
  codeql query run "$Q/UnboundedCopyTainted.ql"       --database=$HOME/part3/$db/db --threads=0
done
```

For results that go into the write-up (stable, quotable, countable), use `analyze` instead
— both queries carry `@id` and `@kind` metadata, and the tainted one is `path-problem`, so
SARIF also carries the full source→sink path:

```bash
codeql database analyze $HOME/part3/ppp-vuln/db "$Q/UnboundedCopyTainted.ql" \
    --format=sarif-latest --output=tainted-ppp-vuln.sarif
```

## 5. Results

### `UnboundedCopyToFixedBuffer.ql` — measured on the VM

Evaluation 30 s per pppd database cold, ~2.5 s warm; 1.6–7 s for the variant.

| Database | Hits | Detail |
| -------- | ---- | ------ |
| `ppp-vuln` (2.4.8) | 4 | `eap.c:1428` in `eap_request()` — **the CVE**; `eap.c:1854` in `eap_response()` — free variant analysis, same bug, different call path; plus `chat.c:1509` in `get_string()` (`temp`, 1024 B, length `minlen`) and `sendserver.c:104` in `rc_pack_list()` (`passbuf`, 48 B, length `length`) |
| `ppp-fixed` (`8d7970b8`) | 2 | **both `rhostname` hits gone**; `chat.c` and `sendserver.c` remain |
| variant (`tlv_server.c`) | 2 | `tlv_server.c:80` in `handle_hello()` (`name`, 64 B, length `vlen`) and `tlv_server.c:145` in `handle_stat()` (`report`, 32 B, length `blen`); **no hit** in `handle_echo()`, which bounds `vlen` against `sizeof(buf)` |

The vuln-minus-fixed difference is the result: patch `8d7970b8` touches only `eap.c`, and
only the `eap.c` findings disappear. No query edits between the two runs.

`chat.c:1509` and `sendserver.c:104` survive the patch, so they are not the CVE, and both are
dropped by the tainted query because neither length is network-derived.

`chat.c:1509` was then read and is a **confirmed false positive**: line 1400 returns rather
than truncating, so `len <= STR_LEN` at the copy and `minlen = max(len, sizeof(fail_buffer)) - 1
<= 1023 < sizeof(temp)`. The guard bounds `len`; the copy length `minlen` is derived from it,
and carrying the bound across that derivation needs range analysis. See the ablation note
below.

`sendserver.c:104` is **untriaged** — out of scope under taint either way, but unread, so no
claim either direction.

### `UnboundedCopyTainted.ql` — measured

Predictions were recorded before each run — 2 / 0 / 1 first, then 2 / 0 / 2 once `handle_stat`
was added. **Both held exactly.**

| Database | Findings | Paths | Detail |
| -------- | -------- | ----- | ------ |
| `ppp-vuln` | **2** | 4 | `eap.c:1428` and `eap.c:1854`. `chat.c` and `sendserver.c` are gone — they were unguarded copies of local data, never attacker-reachable. Precision 2/2. |
| `ppp-fixed` | **0** | 0 | empty `#select`, empty edges and nodes. Nothing at all. |
| variant | **2** | 4 | `tlv_server.c:80` `handle_hello`, `tlv_server.c:145` `handle_stat`. `handle_echo` silent. |

Evaluation 18.6 s / 10.9 s / 9.1 s (sink-only: 2.5 / 2.9 / 4.6 s). Adding `handle_stat`
changed nothing on either pppd database, which is what it should do.

### Ablation — does global value numbering earn its place?

Comment the value-number conjunct out of `lengthCheckedAgainstDestSize`, change nothing else,
rerun. The weaker query is then the naive *"is there any comparison here with an operand that
is `sizeof(dest)`?"*. Measured:

| Database | Sink-only | Tainted |
| -------- | --------- | ------- |
| `ppp-vuln` | 4 → **3** | 2 → **2** |
| `ppp-fixed` | 2 → **1** | 0 → **0** |
| variant | 2 → **1** | 2 → **1** |

Two findings disappear, and they are different kinds of thing.

- `tlv_server.c:145` `handle_stat` — **a true positive lost**, the case it was built for.
  `hlen >= sizeof(report)` satisfies the bound half on its own, so without value numbering the
  copy looks guarded.
- `chat.c:1509` `get_string` — **a false positive lost**, by accident. The weak query accepts
  `len > STR_LEN` because `STR_LEN` is the literal 1024 = `sizeof(temp)`, without caring that
  the guarded value is `len` while the copy length is `minlen`. Reading the source
  (`chat.c:1387–1410`) confirms the copy really is safe: line 1400 *returns* rather than
  truncating, so `len <= 1024` at the copy and `minlen = max(len, sizeof(fail_buffer)) - 1 <= 1023`.
  The query cannot see that — the guard bounds a *predecessor* of the copy length, which needs
  range analysis, not value equality.

| Query | Effect of removing value numbering |
| ----- | ---------------------------------- |
| Sink-only | loses one true positive **and** one false positive — a trade |
| **Tainted** | loses one true positive and nothing else — **pure gain** |

`chat.c` never reaches the tainted results, so on the deliverable query value numbering costs
nothing. The trade exists only on the baseline instrument — visible only because the two
queries are kept separate.

Reproduce: comment line 97 of `CopyToFixedBuffer.qll`, rerun the loop above, then
`git checkout codeql/CopyToFixedBuffer.qll`. No database rebuild — only the query changes.

**Two path shapes inside one file.** The variant's `nodes` table shows `handle_stat` reached
through `payload` → *access to array* → `blen` (a single subscript, `payload[1]`), and
`handle_hello` through `payload` → `... | ...` → `vlen` (the shift-and-or that combines two
bytes). Same source, same sink kind, different expression forms in between, both followed.

**Taint crossed the function-pointer table in both programs.** `eap_request` is reachable
only via `protent.input` → `eap_input`, `handle_hello` only via `ops[i].handle`, and taint
arrived at both. That was the largest open risk in the Part 3 plan, and it is now closed.

**Findings vs paths.** Each finding is listed twice, with `inp` and `*inp` as sources on
pppd, `payload` and `*payload` on the variant. Not a duplicate bug: `asParameter(_)` matches
the parameter at every indirection level, so taint arrives both as the pointer and through
its pointee. Two real paths to one sink, and `path-problem` prints one row per path. Report
counts as "2 findings, 4 paths".

**The path itself is worth showing.** On pppd the `nodes` table is 39 entries and reads
`inp` → `*inp` → `... ++` → `... = ...` → `... -= ...` → `len` → `... - ...`: the pointer
walks forward, the length is reassigned and decremented, and the last node is the copy
length. That is the write-up's §5 argument produced mechanically, and it is why plain data
flow would fail — the original value never survives, only its influence. The variant's path
is 4 nodes: `payload` → the byte-combining expression → `vlen`. Same query, same bug class,
chains differing by a factor of forty.

## Limitations and what remains

- **Guard scope is the whole function**, not "guard control-flow-dominates the sink". Sound
  enough for both targets; tighten with `GuardCondition.controls(...)` if triage turns up a
  false negative.
- **Stack buffers only** (`LocalVariable`). Globals and heap allocations are out of scope.
- **Byte-element arrays assumed** — `destSize` is the array's size in bytes, compared
  directly against a `memcpy` length. True for `char[]` in both targets.
- **Copy-family calls only.** pppd's one-byte NUL write `rhostname[len - vallen] = '\0'`
  (`eap.c:1429`) is a second out-of-bounds write and is not matched.
- **Dispatch-table sources are an over-approximation.** Any function stored in a
  function-pointer table has all its parameters treated as attacker-controlled. Justified
  for protocol dispatchers, wrong in general — state it in the write-up rather than hiding
  it.
- **No range analysis**, so a guard on a *predecessor* of the copy length is invisible. This is
  the one confirmed false positive: `chat.c:1509` bounds `len` and copies `minlen`, which is
  derived from `len`. The clamp idiom `if (n > N) n = N;` is the simplest case of the same gap.
  Fixing it means interval reasoning, not another value-equality test.
