# codeql-buffer-overflow-variant

A deliberately vulnerable, ~130-line C program used as a **CodeQL static-analysis
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

A bounds check is present — it just checks the wrong thing: the declared length
is validated against the received frame (preventing an over-read) but never
against `sizeof(dest)` (which is what prevents the over-write). This is the same
root cause as pppd's dead `vallen >= len + sizeof(rhostname)` check.

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

- `handle_hello()` — **vulnerable**. `memcpy(name, payload + 2, vlen)` with `vlen`
  bounded by the frame, not by `sizeof(name)`.
- `handle_echo()` — **safe**. Same source and sink shape, but `vlen` is also
  bounded by `sizeof(buf)`. This is the **negative control**: the query must fire
  on `handle_hello` and stay silent here.

## Wire format

One UDP datagram = one frame:

```
[ type : 1 ] [ length : 2, big-endian ] [ value : length bytes ]
```

`type` 0x01 → hello, 0x02 → echo. A hello frame with a declared length between 65
and ~2045 overflows `name[64]`.

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

Then run the Part 3 query against `db`; it should report the `memcpy` in
`handle_hello` and not the one in `handle_echo`.
