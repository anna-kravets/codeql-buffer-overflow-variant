# codeql-buffer-overflow-variant

A deliberately vulnerable, ~170-line C program used as a **CodeQL static-analysis
target**. It reproduces the *bug class* of **CVE-2020-8597** — the pppd EAP
`rhostname` stack buffer overflow (CWE-120) — in a program that shares none of
pppd's function names, call depth, or dispatch structure.

The goal is a **generality test**: a CodeQL query written to catch the pppd bug
must also fire on this program, unedited. If it does, the query expresses the bug
class rather than the original code's shape.

> This program is intentionally unsafe and exists only for analysis. Do not
> deploy it. The bug it mirrors is public (CVE-2020-8597, disclosed 2020).

## The bug class

> An attacker-derived length is copied into a fixed-size buffer, with no guard
> relating that length to the buffer's size.

In every case a bounds check is present — it just fails to relate the two
quantities that matter. There are exactly two ways to get that wrong, and the
program contains one of each:

- **Right value, wrong bound.** The copy length is checked, but against the
  received frame instead of `sizeof(dest)`. Prevents an over-read, does nothing
  about the over-write. (`handle_hello`)
- **Right bound, wrong value.** The check names `sizeof(dest)` — it looks exactly
  like a buffer bound — but constrains a different variable than the one used as
  the copy length. (`handle_stat`)

The second is the harder one, and it is what pppd's dead
`vallen >= len + sizeof(rhostname)` check is: a comparison that mentions the
destination size while constraining something that is not the copy length. A
query that only asks *"does some comparison here mention `sizeof(dest)`?"* is
silenced by it.

## Structure vs. pppd (why it's a real variant)

| | pppd / CVE-2020-8597 | this project |
| - | -------------------- | ------------ |
| Source | `read()` on the PPP fd | `recvfrom()` on a UDP socket |
| Dispatch | global `struct protent *protocols[]`, linear match on protocol no. | file-local `const struct frame_op ops[]`, linear match on 1-byte tag |
| Depth to sink | `get_input` → `(*input)` → `eap_input` → `eap_request` | `dispatch_frame` → `(*handle)` → `handle_hello` |
| Destination | `char rhostname[256]` | `char name[64]` |
| Wrong guard | `vallen` bounded by packet `len` | `vlen` bounded by frame `plen` |

Both keep the one property that makes this data-flow, not grep: an **indirect
call through a function-pointer table** between the source and the sink.

| Handler | Line | Check present | Verdict |
| ------- | ---- | ------------- | ------- |
| `handle_hello()` | sink at `:80` | `vlen > plen - 2` — right value, wrong bound | **must fire** |
| `handle_echo()` | copy at `:106` | `vlen >= sizeof(buf)` — both right | **must stay silent** — negative control |
| `handle_stat()` | sink at `:145` | `hlen >= sizeof(report)` — right bound, wrong value | **must fire** |

`handle_stat` is the discriminating case. Its check names `sizeof(report)`, so a
query that accepts any comparison mentioning the destination size treats it as
guarded and misses the bug. Catching it requires comparing the *value* being
checked against the *value* used as the copy length — global value numbering.
Delete that from the query and this handler becomes a false negative while every
other site keeps its verdict.

## Wire format

One UDP datagram = one frame:

```
[ type : 1 ] [ length : 2, big-endian ] [ value : length bytes ]
```

`type` 0x01 → hello, 0x02 → echo, 0x03 → stat. A hello frame with a declared
length between 65 and ~2045 overflows `name[64]`. A stat frame carries two
one-byte lengths instead — a header length and a body length — and any body
length above 32 overflows `report[32]`, whatever the header length says.

## Build

```sh
make            # gcc -Wall -Wextra -O0 -g -o tlv_server tlv_server.c
```

Linux/POSIX (BSD sockets). Builds clean with no warnings.

## Build a CodeQL database

CodeQL traces a real compile, so build from clean:

```sh
make clean
codeql database create db --language=cpp --command="make"
# or, without the clean step:
codeql database create db --language=cpp --command="make -B"
```

Then run the Part 3 queries against `db`; they should report the `memcpy` in
`handle_hello` and the one in `handle_stat`, and stay silent on `handle_echo`.
The queries and their run instructions live in [`codeql/`](codeql/).

The source changes whenever a handler is added, so **rebuild the database** —
CodeQL snapshots the code at `database create` time and an existing `db/` will
not see new code.
