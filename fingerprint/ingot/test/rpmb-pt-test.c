// SPDX-License-Identifier: MIT
/*
 * rpmb-pt-test: the RPMB pass-through's request handling on the host
 * (make rpmb-pt-test). A fake transport records every SECURITY PROTOCOL
 * transfer and answers with canned frames, so this checks what reaches the
 * device, what comes back where, every refusal, and that the log never
 * holds a data block or a MAC. The "device" is /dev/null (a character
 * device the open accepts); nothing else on the machine is touched.
 */

#include "omamobile-rpmb-pt.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SB_LEN		0x6400u
#define F_MAC		196u
#define F_DATA		228u
#define F_NONCE		484u
#define F_COUNTER	500u
#define F_ADDR		504u
#define F_COUNT		506u
#define F_RESULT	508u
#define F_TYPE		510u

static int failures;

#define check(cond, ...) do { \
	if (cond) { printf("ok - " __VA_ARGS__); printf("\n"); } \
	else { printf("not ok - " __VA_ARGS__); printf(" (%s:%d)\n", __FILE__, __LINE__); failures++; } \
} while (0)

/* ---- the fake transport ---- */

struct call {
	int dir_in;
	size_t len;
	uint8_t first[RPMB_PT_FRAME];	/* the first frame sent, or zero */
};

static struct {
	struct call calls[16];
	int n;
	int fail_at;		/* the call index that fails, or -1 */
	int fail_status;
	/* what an IN gets: a reply frame pattern, repeated */
	uint8_t reply[RPMB_PT_FRAME];
} fake;

static int fake_xfer(void *ctx, int dir_in, void *buf, size_t len, char *err,
		     size_t errlen)
{
	struct call *c;
	size_t i;

	(void)ctx;
	if (fake.n >= 16)
		return -1;
	c = &fake.calls[fake.n];
	c->dir_in = dir_in;
	c->len = len;
	if (!dir_in)
		memcpy(c->first, buf, RPMB_PT_FRAME);
	if (fake.n == fake.fail_at) {
		fake.n++;
		snprintf(err, errlen, "fake failure");
		return fake.fail_status;
	}
	if (dir_in)
		for (i = 0; i + RPMB_PT_FRAME <= len; i += RPMB_PT_FRAME)
			memcpy((uint8_t *)buf + i, fake.reply, RPMB_PT_FRAME);
	fake.n++;
	return 0;
}

static void fake_reset(void)
{
	memset(&fake, 0, sizeof(fake));
	fake.fail_at = -1;
}

static void put16(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint32_t get16(const uint8_t *p)
{
	return (uint32_t)p[0] << 8 | p[1];
}

static void hdr(unsigned char *sb, uint32_t off, uint32_t v)
{
	memcpy(sb + off, &v, 4);
}

static uint32_t hdrv(const unsigned char *sb, uint32_t off)
{
	uint32_t v;

	memcpy(&v, sb + off, 4);
	return v;
}

/* A request frame of the given type at sb + 0x18 + i * 512. */
static uint8_t *req_frame(unsigned char *sb, uint32_t i, uint32_t type,
			  uint32_t addr, uint32_t count, uint32_t counter)
{
	uint8_t *f = sb + 0x18 + i * RPMB_PT_FRAME;

	memset(f, 0, RPMB_PT_FRAME);
	memset(f + F_DATA, 'D', 256);		/* a "data block" */
	memset(f + F_MAC, 'M', 32);		/* a "MAC" */
	memcpy(f + F_NONCE, "\xa7\xb3\x6b\x67NONCE-NONCE", 16);
	put32(f + F_COUNTER, counter);
	put16(f + F_ADDR, addr);
	put16(f + F_COUNT, count);
	put16(f + F_TYPE, type);
	return f;
}

/* The canned reply: response type, result, counter, addr, count, and
 * a data/MAC pattern the log must never show. */
static void canned(uint32_t resp, uint32_t result, uint32_t counter,
		   uint32_t addr, uint32_t count)
{
	memset(fake.reply, 0, sizeof(fake.reply));
	memset(fake.reply + F_DATA, 'R', 256);
	memset(fake.reply + F_MAC, 'K', 32);
	put32(fake.reply + F_COUNTER, counter);
	put16(fake.reply + F_ADDR, addr);
	put16(fake.reply + F_COUNT, count);
	put16(fake.reply + F_RESULT, result);
	put16(fake.reply + F_TYPE, resp);
}

static char logpath[256];

static char *read_log(void)
{
	static char buf[65536];
	FILE *f = fopen(logpath, "r");
	size_t n = 0;

	buf[0] = 0;
	if (!f)
		return buf;
	n = fread(buf, 1, sizeof(buf) - 1, f);
	buf[n] = 0;
	fclose(f);
	return buf;
}

int main(void)
{
	struct rpmb_pt p;
	unsigned char sb[SB_LEN];
	char err[256], desc[1024], dir[] = "/tmp/rpmb-pt-test.XXXXXX", *log;
	char path[300];
	uint32_t len;
	struct stat st;

	if (!mkdtemp(dir)) {
		perror("mkdtemp");
		return 1;
	}
	snprintf(logpath, sizeof(logpath), "%s/passthrough.log", dir);

	/* ---- open ---- */
	snprintf(path, sizeof(path), "%s/notadevice", dir);
	close(open(path, O_WRONLY | O_CREAT, 0600));
	check(rpmb_pt_open(&p, path, logpath, 0, 248, 32768, err, sizeof(err)) == -1 &&
	      strstr(err, "not a character device"), "open: a regular file as the device is refused (%s)", err);
	check(rpmb_pt_open(&p, "", logpath, 0, 248, 32768, err, sizeof(err)) == -1, "open: no device path is refused");
	check(rpmb_pt_open(&p, "/dev/null", logpath, 0, 0, 32768, err, sizeof(err)) == -1 &&
	      strstr(err, "frames per transfer"), "open: frames per transfer 0 is refused");
	snprintf(path, sizeof(path), "%s/link.log", dir);
	check(symlink("/etc/hostname", path) == 0 &&
	      rpmb_pt_open(&p, "/dev/null", path, 0, 248, 32768, err, sizeof(err)) == -1,
	      "open: a symlink as the log is refused (%s)", err);
	check(rpmb_pt_open(&p, "/dev/null", logpath, 0, 248, 32768, err, sizeof(err)) == 0,
	      "open: /dev/null (a character device) and the log: %s", err[0] ? err : "ok");
	check(stat(logpath, &st) == 0 && S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0600,
	      "open: the log is created as a regular file, 0600");
	check(rpmb_pt_request_sense(&p, err, sizeof(err)) != 0 && strstr(err, "request-sense"),
	      "request sense on /dev/null: reported as a failure, the init goes on (%s)", err);
	p.xfer = fake_xfer;
	p.xfer_ctx = NULL;

	/* ---- 0x101 ---- */
	memset(sb, 0, sizeof(sb));
	hdr(sb, 0, 0x101); hdr(sb, 4, 1);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(len == 20 && hdrv(sb, 0) == 0x101 && hdrv(sb, 4) == 1 && hdrv(sb, 8) == 0 &&
	      hdrv(sb, 12) == 32768 && hdrv(sb, 16) == 248, "0x101 sub 1: {0x101, 1, 0, sectors, fpt}: %s", desc);
	hdr(sb, 0, 0x101); hdr(sb, 4, 0);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(len == 20 && hdrv(sb, 8) == 0xffffffffu && hdrv(sb, 12) == 0, "0x101 sub 0: the constant reply");
	hdr(sb, 0, 0x101); hdr(sb, 4, 2);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(len == 40 && hdrv(sb, 4) == 2 && hdrv(sb, 20) == 9, "0x101 other: 40 bytes, type 9");

	/* ---- 0x102, one transfer ---- */
	fake_reset();
	canned(0x0400, 0x0007, 0, 0xa6, 6);
	memset(sb, 0, sizeof(sb));
	hdr(sb, 0, 0x102); hdr(sb, 4, 6); hdr(sb, 0xc, 0x18);
	req_frame(sb, 0, RPMB_PT_REQ_AUTH_READ, 0xa6, 0, 0);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(len == 20 && hdrv(sb, 4) == 0 && hdrv(sb, 8) == 6 * 512 && hdrv(sb, 0xc) == 20,
	      "0x102 read of 6: header status 0, 3072 bytes moved, 20");
	check(fake.n == 2 && !fake.calls[0].dir_in && fake.calls[0].len == 512 &&
	      get16(fake.calls[0].first + F_TYPE) == RPMB_PT_REQ_AUTH_READ &&
	      fake.calls[1].dir_in && fake.calls[1].len == 3072,
	      "0x102: one SECURITY PROTOCOL OUT of the request frame, one IN of 6 frames");
	check(get16(sb + 0x14 + 5 * 512 + F_TYPE) == 0x0400 && get16(sb + 0x14 + 5 * 512 + F_RESULT) == 0x0007 &&
	      sb[0x14 + F_DATA] == 'R', "0x102: the chip's frames land at +0x14 unmodified");
	check(strstr(desc, "request 4: command 0x102, frames 6 (248 per tx): tx1 auth-read addr 0x00a6 k 6 nonce=a7b36b67.. spo 512 ok, spi 3072 ok, resp 0x0400 addr 0x00a6 count 6 counter 0 -> result 0x0007"),
	      "0x102: the decode line: %s", desc);

	/* ---- 0x102, two transfers (fpt 4), the second request frame kept ---- */
	fake_reset();
	canned(0x0400, 0x0000, 0, 0x10, 4);
	p.fpt = 4;
	memset(sb, 0, sizeof(sb));
	hdr(sb, 0, 0x102); hdr(sb, 4, 6); hdr(sb, 0xc, 0x18);
	req_frame(sb, 0, RPMB_PT_REQ_AUTH_READ, 0x10, 0, 0);
	req_frame(sb, 1, RPMB_PT_REQ_AUTH_READ, 0x14, 0, 0);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(len == 20 && hdrv(sb, 4) == 0 && hdrv(sb, 8) == 6 * 512 && fake.n == 4 &&
	      fake.calls[1].dir_in && fake.calls[1].len == 2048 &&
	      !fake.calls[2].dir_in && get16(fake.calls[2].first + F_ADDR) == 0x14 &&
	      fake.calls[3].dir_in && fake.calls[3].len == 1024,
	      "0x102 of 6 with 4 per transfer: OUT, IN 2048, OUT (the second request frame, copied before the first reply overwrote it), IN 1024");
	check(strstr(desc, "tx1 auth-read addr 0x0010 k 4") && strstr(desc, "; tx2 auth-read addr 0x0014 k 2"),
	      "0x102 two transfers: both decoded: %s", desc);
	p.fpt = 248;

	/* ---- 0x102 read counter ---- */
	fake_reset();
	canned(0x0200, 0x0000, 17, 0, 0);
	memset(sb, 0, sizeof(sb));
	hdr(sb, 0, 0x102); hdr(sb, 4, 1); hdr(sb, 0xc, 0x18);
	req_frame(sb, 0, RPMB_PT_REQ_READ_CTR, 0, 0, 0);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(len == 20 && hdrv(sb, 4) == 0 && fake.n == 2 && strstr(desc, "tx1 read-counter addr 0x0000 k 1") &&
	      strstr(desc, "resp 0x0200 addr 0x0000 count 0 counter 17 -> result 0x0000"),
	      "0x102 read counter: passed through, the counter logged: %s", desc);

	/* ---- refusals on the read path ---- */
	fake_reset();
	memset(sb, 0, sizeof(sb));
	hdr(sb, 0, 0x102); hdr(sb, 4, 1); hdr(sb, 0xc, 0x18);
	req_frame(sb, 0, RPMB_PT_REQ_PROGRAM_KEY, 0, 0, 0);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(len == 20 && hdrv(sb, 4) == 0xffffffffu && hdrv(sb, 8) == 0 && fake.n == 0 &&
	      strstr(desc, "REFUSED program-key request type 0x0001 -> status -1"),
	      "0x102 with a PROGRAM KEY frame: refused before any I/O: %s", desc);
	fake_reset();
	memset(sb, 0, sizeof(sb));
	hdr(sb, 0, 0x102); hdr(sb, 4, 0); hdr(sb, 0xc, 0x18);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(len == 20 && hdrv(sb, 4) == 0xffffffffu && fake.n == 0, "0x102 of 0 frames: refused");
	hdr(sb, 0, 0x102); hdr(sb, 4, 50); hdr(sb, 0xc, 0x18);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(len == 20 && hdrv(sb, 4) == 0xffffffffu && fake.n == 0, "0x102 of 50 frames (past the buffer): refused");
	hdr(sb, 0, 0x102); hdr(sb, 4, 1); hdr(sb, 0xc, SB_LEN - 100);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(len == 20 && hdrv(sb, 4) == 0xffffffffu && fake.n == 0, "0x102 with a frame offset past the buffer: refused");

	/* ---- a transport failure ---- */
	fake_reset();
	fake.fail_at = 1;
	fake.fail_status = -5;
	memset(sb, 0, sizeof(sb));
	hdr(sb, 0, 0x102); hdr(sb, 4, 1); hdr(sb, 0xc, 0x18);
	req_frame(sb, 0, RPMB_PT_REQ_AUTH_READ, 0, 0, 0);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(len == 20 && hdrv(sb, 4) == 0xfffffffbu && hdrv(sb, 8) == 0 && fake.n == 2 &&
	      strstr(desc, "spi FAILED (fake failure) -> status -5"),
	      "0x102 with the IN failing: status -5 in the header: %s", desc);

	/* ---- 0x103, writes refused (the default) ---- */
	fake_reset();
	memset(sb, 0, sizeof(sb));
	hdr(sb, 0, 0x103); hdr(sb, 4, 1); hdr(sb, 0xc, 0x18); hdr(sb, 0x14, 1);
	req_frame(sb, 0, RPMB_PT_REQ_AUTH_WRITE, 0x10, 1, 5);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	/* +0x14 (w4 on the way in, the result frame on the way out) and the
	 * frames after it stay as they were: nothing is made up */
	check(len == 20 && hdrv(sb, 4) == 0xffffffffu && hdrv(sb, 8) == 0 && fake.n == 0 && hdrv(sb, 0x14) == 1 &&
	      sb[0x18 + F_DATA] == 'D' && get16(sb + 0x18 + F_TYPE) == RPMB_PT_REQ_AUTH_WRITE &&
	      strstr(desc, "command 0x103, frames 1 (1 per tx): REFUSED writes disabled (type 0x0003 addr 0x0010 k 1 counter 5) -> status -1"),
	      "0x103 with writes off: refused, no I/O, the buffer past the header untouched: %s", desc);
	check(p.refused == 5, "the refusals are counted (%lu)", p.refused);

	/* ---- 0x103, writes enabled ---- */
	p.writes = 1;
	fake_reset();
	canned(0x0300, 0x0000, 6, 0x10, 0);
	memset(sb, 0, sizeof(sb));
	hdr(sb, 0, 0x103); hdr(sb, 4, 1); hdr(sb, 0xc, 0x18); hdr(sb, 0x14, 1);
	req_frame(sb, 0, RPMB_PT_REQ_AUTH_WRITE, 0x10, 1, 5);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(len == 20 && hdrv(sb, 4) == 0 && hdrv(sb, 8) == 512 && hdrv(sb, 0xc) == 20,
	      "0x103 write of 1: header status 0, 512 bytes moved");
	check(fake.n == 3 && !fake.calls[0].dir_in && fake.calls[0].len == 512 &&
	      get16(fake.calls[0].first + F_TYPE) == RPMB_PT_REQ_AUTH_WRITE && fake.calls[0].first[F_DATA] == 'D' &&
	      fake.calls[0].first[F_MAC] == 'M' &&
	      !fake.calls[1].dir_in && fake.calls[1].len == 512 && fake.calls[2].dir_in && fake.calls[2].len == 512,
	      "0x103: OUT of the data frame unmodified, OUT of the result-read frame, IN of the result frame");
	{
		static const uint8_t zero[RPMB_PT_FRAME];
		const uint8_t *rr = fake.calls[1].first;

		check(!memcmp(rr, zero, 511) && rr[511] == 0x05, "0x103: the result-read frame is all zero but type 0x0005");
	}
	check(get16(sb + 0x14 + F_TYPE) == 0x0300 && get16(sb + 0x14 + F_RESULT) == 0 && sb[0x14 + F_MAC] == 'K',
	      "0x103: the chip's result frame lands at +0x14 unmodified");
	check(strstr(desc, "tx1 auth-write addr 0x0010 k 1 counter 5 spo 512 ok, spo result-read ok, spi 512 ok, resp 0x0300 addr 0x0010 counter 6 -> result 0x0000"),
	      "0x103: the decode line: %s", desc);

	/* two transfers of 2 frames */
	fake_reset();
	canned(0x0300, 0x0000, 8, 0x20, 0);
	memset(sb, 0, sizeof(sb));
	hdr(sb, 0, 0x103); hdr(sb, 4, 4); hdr(sb, 0xc, 0x18); hdr(sb, 0x14, 2);
	req_frame(sb, 0, RPMB_PT_REQ_AUTH_WRITE, 0x20, 2, 7);
	req_frame(sb, 1, RPMB_PT_REQ_AUTH_WRITE, 0x20, 2, 7);
	req_frame(sb, 2, RPMB_PT_REQ_AUTH_WRITE, 0x22, 2, 8);
	req_frame(sb, 3, RPMB_PT_REQ_AUTH_WRITE, 0x22, 2, 8);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(len == 20 && hdrv(sb, 4) == 0 && fake.n == 6 && fake.calls[0].len == 1024 && fake.calls[3].len == 1024 &&
	      get16(fake.calls[3].first + F_ADDR) == 0x22 && strstr(desc, "; tx2 auth-write addr 0x0022 k 2 counter 8"),
	      "0x103 of 4 frames, 2 per transfer: two rounds, the second's frames intact: %s", desc);

	/* refusals on the write path, writes enabled */
	fake_reset();
	memset(sb, 0, sizeof(sb));
	hdr(sb, 0, 0x103); hdr(sb, 4, 1); hdr(sb, 0xc, 0x18); hdr(sb, 0x14, 1);
	req_frame(sb, 0, RPMB_PT_REQ_PROGRAM_KEY, 0, 1, 0);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(len == 20 && hdrv(sb, 4) == 0xffffffffu && fake.n == 0 && strstr(desc, "REFUSED program-key request type 0x0001"),
	      "0x103 PROGRAM KEY with writes enabled: still refused before any I/O: %s", desc);
	memset(sb, 0, sizeof(sb));
	hdr(sb, 0, 0x103); hdr(sb, 4, 2); hdr(sb, 0xc, 0x18); hdr(sb, 0x14, 1);
	req_frame(sb, 0, RPMB_PT_REQ_AUTH_WRITE, 0, 1, 0);
	req_frame(sb, 1, RPMB_PT_REQ_PROGRAM_KEY, 0, 1, 0);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(hdrv(sb, 4) == 0xffffffffu && fake.n == 0, "0x103 with a PROGRAM KEY frame in a later transfer: refused whole");
	hdr(sb, 0, 0x103); hdr(sb, 4, 3); hdr(sb, 0xc, 0x18); hdr(sb, 0x14, 2);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(hdrv(sb, 4) == 0xffffffffu && fake.n == 0 && strstr(desc, "REFUSED bad frame counts"), "0x103 of 3 frames, 2 per transfer: refused");
	hdr(sb, 0, 0x103); hdr(sb, 4, 249); hdr(sb, 0xc, 0x18); hdr(sb, 0x14, 249);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(hdrv(sb, 4) == 0xffffffffu && fake.n == 0, "0x103 with more per transfer than the device takes: refused");
	p.writes = 0;

	/* ---- 0x104 and unknown ---- */
	memset(sb, 0, sizeof(sb));
	hdr(sb, 0, 0x104); hdr(sb, 4, 0x200);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(len == 16 && hdrv(sb, 4) == 0xffffffffu && hdrv(sb, 12) == 16, "0x104: not found, 16 bytes");
	hdr(sb, 0, 0x177);
	len = rpmb_pt_serve(&p, sb, SB_LEN, desc, sizeof(desc));
	check(len == 20 && hdrv(sb, 0) == 0x177 && hdrv(sb, 4) == 0xfffffff9u && hdrv(sb, 12) == 20, "unknown command: status -7, 20 bytes");

	/* ---- the log ---- */
	rpmb_pt_log(&p, "a banner line");
	log = read_log();
	check(strstr(log, "Z request 1: command 0x101") && strstr(log, "REFUSED writes disabled") &&
	      strstr(log, "tx1 auth-write addr 0x0010 k 1 counter 5") && strstr(log, "Z a banner line\n"),
	      "the log has every request's line and the banner, timestamped");
	check(!strstr(log, "DDDD") && !strstr(log, "RRRR") && !strstr(log, "MMMM") && !strstr(log, "KKKK") &&
	      !strstr(log, "NONCE-NONCE"), "the log holds no data block, no MAC, no full nonce");
	check(p.requests == 20, "20 requests served (%lu)", p.requests);
	rpmb_pt_close(&p);
	check(p.dev_fd == -1 && p.log_fd == -1, "close");

	unlink(logpath);
	snprintf(path, sizeof(path), "%s/notadevice", dir); unlink(path);
	snprintf(path, sizeof(path), "%s/link.log", dir); unlink(path);
	rmdir(dir);
	printf("%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
	return failures ? 1 : 0;
}
