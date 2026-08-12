/*
 * tlv_server.c — synthetic variant for the CVE-2020-8597 CodeQL exercise.
 *
 * A tiny UDP "TLV" frame parser that reproduces the *bug class* of
 * CVE-2020-8597 (pppd EAP `rhostname` stack overflow, CWE-120) while sharing
 * none of its identifiers, call depth or dispatch shape. The point is a
 * generality test: a CodeQL query written against the pppd bug must also fire
 * here, without edits.
 *
 * Bug class:
 *   an attacker-derived length copied into a fixed-size buffer, with no guard
 *   relating that length to the buffer's size. A guard *exists* — but it
 *   compares the length against the received frame, not against sizeof(dest).
 *
 * Wire format (one datagram = one frame):
 *   [ type : 1 byte ] [ length : 2 bytes, big-endian ] [ value : length bytes ]
 *
 * This program is intentionally vulnerable and exists only as a static-analysis
 * target. Do not deploy it.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LISTEN_PORT 4000
#define RECV_BUF    2048

enum { TLV_HELLO = 0x01, TLV_ECHO = 0x02 };

static void handle_hello(const uint8_t *payload, size_t plen);
static void handle_echo(const uint8_t *payload, size_t plen);

/*
 * Dispatch table. Deliberately a different shape from pppd's
 * `struct protent *protocols[]`: a file-local const array of *value* structs,
 * matched on a one-byte tag, resolved by linear scan to an indirect call.
 */
struct frame_op {
	uint8_t tag;
	void  (*handle)(const uint8_t *payload, size_t plen);
};

static const struct frame_op ops[] = {
	{ TLV_HELLO, handle_hello },
	{ TLV_ECHO,  handle_echo  },
};

/*
 * VULNERABLE — the analogue of pppd's eap_request().
 *
 * `vlen` is read out of the packet and validated against the frame length
 * `plen`. That check is real (it prevents an over-read past the received
 * bytes) but it is the wrong check: nothing relates `vlen` to sizeof(name).
 * For 64 < vlen <= plen-2 the memcpy writes past `name`, exactly as pppd's
 * copy is bounded by the packet rather than by sizeof(rhostname).
 */
static void handle_hello(const uint8_t *payload, size_t plen)
{
	char name[64];

	if (plen < 2)
		return;

	/* length field re-read from attacker bytes (cf. pppd's GETSHORT) */
	size_t vlen = ((size_t)payload[0] << 8) | (size_t)payload[1];

	if (vlen > plen - 2) {                 /* bounds the FRAME, not the BUFFER */
		fprintf(stderr, "hello: declared length %zu exceeds frame\n", vlen);
		return;
	}

	memcpy(name, payload + 2, vlen);       /* SINK: vlen never checked vs sizeof(name) */
	name[vlen] = '\0';                     /* extra 1-byte OOB write, as in pppd */
	printf("hello from %s\n", name);
}

/*
 * SAFE — negative control for the false-positive check.
 *
 * Same source, same sink shape, but `vlen` is additionally bounded by
 * sizeof(buf) before the copy. The query's barrier (a comparison of the length
 * operand against sizeof(dest)) must recognise this and leave it alone.
 */
static void handle_echo(const uint8_t *payload, size_t plen)
{
	char buf[128];

	if (plen < 2)
		return;

	size_t vlen = ((size_t)payload[0] << 8) | (size_t)payload[1];

	if (vlen > plen - 2 || vlen >= sizeof(buf)) {   /* bounded against the destination */
		fprintf(stderr, "echo: bad length %zu\n", vlen);
		return;
	}

	memcpy(buf, payload + 2, vlen);
	buf[vlen] = '\0';
	printf("echo: %s\n", buf);
}

static void dispatch_frame(const uint8_t *frame, size_t n)
{
	if (n < 3)                             /* need type + 2-byte length */
		return;

	uint8_t type = frame[0];
	const uint8_t *payload = frame + 1;    /* [ length:2 ][ value... ] */
	size_t plen = n - 1;

	for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
		if (ops[i].tag == type) {
			ops[i].handle(payload, plen);  /* INDIRECT CALL through the table */
			return;
		}
	}
}

int main(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(LISTEN_PORT);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(fd);
		return 1;
	}

	for (;;) {
		uint8_t buf[RECV_BUF];
		ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);  /* SOURCE: attacker bytes */
		if (n < 0) {
			perror("recvfrom");
			break;
		}
		dispatch_frame(buf, (size_t)n);
	}

	close(fd);
	return 0;
}
