# Part 3 CodeQL queries — running them from the VM

Queries for **CVE-2020-8597**, the pppd EAP `rhostname` stack buffer overflow.

| File | What it is |
| ---- | ---------- |
| `CopyToFixedBuffer.qll` | Shared library: the sink shape and the guard test. Both queries import it, so the only difference between their results is taint. |
| `UnboundedCopyToFixedBuffer.ql` | **Phase 2 step 1** — sink shape only, no taint. Verified on all three databases. |
| `UnboundedCopyTainted.ql` | **Phase 2 steps 2–4** — same sink, plus the length must be attacker-derived. Not yet verified. |
| `SourceProbe.ql` | Diagnostic. Run it before the taint query. |

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

`UnboundedCopyTainted.ql` adds a fourth condition: taint must reach the length operand
from either a `RemoteFlowSource` or a dispatch-table handler's parameter. See
[`query-explained.md`](query-explained.md) for why the second source kind is needed.

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
| `semmle.code.cpp.security.FlowSources` | drop the `RemoteFlowSource` disjunct entirely and rely on dispatch-table parameters; record this in the write-up as a limitation |
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
| variant (`tlv_server.c`) | 1 | `tlv_server.c:78` in `handle_hello()`; **no hit** at `tlv_server.c:104` in `handle_echo()`, which bounds `vlen` against `sizeof(buf)` |

The vuln-minus-fixed difference is the result: patch `8d7970b8` touches only `eap.c`, and
only the `eap.c` findings disappear. No query edits between the two runs.

`chat.c:1509` and `sendserver.c:104` survive the patch, so they are not the CVE. Neither is
confirmed a false positive — the sink-only query has no notion of "attacker-controlled", so
a hit means "unguarded", not "exploitable". `chat.c` is the dial-script tool, where `minlen`
derives from the expect string, i.e. local config; `sendserver.c` is the RADIUS plugin
packing an *outgoing* request. Read both before writing either into the report, and look
specifically for a clamp (`if (n > N) n = N;`) — a clamp against a constant that is not
literally the destination size is a genuine precision gap in condition 3, not a source-scope
issue.

### `UnboundedCopyTainted.ql` — prediction, not yet measured

Recorded before running, so the write-up can show a falsifiable claim rather than a demo:

| Database | Predicted | Meaning if it holds |
| -------- | --------- | ------------------- |
| `ppp-vuln` | **2** — `eap.c:1428`, `eap.c:1854` | taint crosses the `protent.input` table and both non-CVE hits are source-scope, not precision, problems |
| `ppp-fixed` | **0** | the guard test still works under taint |
| variant | **1** — `tlv_server.c:78` | taint crosses `ops[i].handle` too |

**Run the variant first** — seconds instead of half a minute, same question. If it returns
0, taint is not crossing the function-pointer table and there is no point spending a pppd
run; fix that first with `SourceProbe.ql`.

The failure mode to watch for is 0 / 0 / 0. That does not mean the code is safe; it means
taint never reached the sink, and the query is silently useless. Any result must be read
against the sink-only numbers above.

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
- **No clamp recognition.** `if (n > N) n = N;` where `N` is a constant smaller than the
  destination is a real guard the query does not see. Add only if triage shows it matters.
