// SPDX-License-Identifier: MIT
/*
 * Host test of the RPMB emulator (stubs/omamobile-rpmb-emu.c): drives the
 * same handlers librpmb.so runs, on a shared buffer laid out as TrustZone
 * lays it out, against a fresh temp directory. HMAC-SHA256 is checked
 * against RFC 4231 vectors and, for the frames' MACs, against python3's
 * hmac module. The key is a made-up pattern. `make rpmb-emu-test`.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "omamobile-rpmb-emu.h"

#define SB_LEN	0x6400u
#define FR	512u

static unsigned char sb[SB_LEN];
static struct rpmb_emu emu;
static uint8_t key[32];
static char desc[768];
static int failures;

#define CHECK(cond, ...) do {						\
	if (!(cond)) {							\
		printf("FAIL %s:%d: ", __FILE__, __LINE__);		\
		printf(__VA_ARGS__);					\
		printf("\n");						\
		failures++;						\
	}								\
} while (0)

static uint32_t w(size_t off)
{
	uint32_t v;

	memcpy(&v, sb + off, 4);
	return v;
}

static void setw(size_t off, uint32_t v)
{
	memcpy(sb + off, &v, 4);
}

static uint32_t g16(const uint8_t *f, size_t off)
{
	return (uint32_t)f[off] << 8 | f[off + 1];
}

static uint32_t g32(const uint8_t *f, size_t off)
{
	return (uint32_t)f[off] << 24 | (uint32_t)f[off + 1] << 16 |
	       (uint32_t)f[off + 2] << 8 | f[off + 3];
}

static void p16(uint8_t *f, size_t off, uint32_t v)
{
	f[off] = (uint8_t)(v >> 8);
	f[off + 1] = (uint8_t)v;
}

static void p32(uint8_t *f, size_t off, uint32_t v)
{
	p16(f, off, v >> 16);
	p16(f, off + 2, v);
}

static uint32_t serve(void)
{
	uint32_t len = rpmb_emu_serve(&emu, sb, SB_LEN, desc, sizeof(desc));

	printf("  %s\n", desc);
	return len;
}

static void hex(char *out, const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		sprintf(out + 2 * i, "%02x", p[i]);
}

/* The test's own reference: python3 -I's hmac over the same bytes. */
static int python_mac(const uint8_t *msg, size_t len, uint8_t out[32])
{
	static char cmd[16384];
	char keyhex[65], line[128];
	unsigned int i, b;
	FILE *p;
	int n;

	hex(keyhex, key, sizeof(key));
	n = snprintf(cmd, sizeof(cmd), "python3 -I -c 'import hmac,hashlib,"
		     "sys;print(hmac.new(bytes.fromhex(sys.argv[1]),bytes."
		     "fromhex(sys.argv[2]),hashlib.sha256).hexdigest())' %s ",
		     keyhex);
	if (n < 0 || (size_t)n + 2 * len + 1 > sizeof(cmd))
		return -1;
	hex(cmd + n, msg, len);
	p = popen(cmd, "r");
	if (!p)
		return -1;
	if (!fgets(line, sizeof(line), p) || strlen(line) < 64) {
		pclose(p);
		return -1;
	}
	pclose(p);
	for (i = 0; i < 32; i++) {
		if (sscanf(line + 2 * i, "%2x", &b) != 1)
			return -1;
		out[i] = (uint8_t)b;
	}
	return 0;
}

/* MAC of k frames, both ours and python's; returns 1 when they agree and
 * match the MAC stored in the last frame. */
static int frames_mac_ok(const uint8_t *frames, uint32_t k)
{
	uint8_t msg[64 * 284], ours[32], ref[32];
	uint32_t i;

	for (i = 0; i < k; i++)
		memcpy(msg + i * 284, frames + i * FR + 228, 284);
	rpmb_emu_hmac_sha256(key, sizeof(key), msg, k * 284, ours);
	if (python_mac(msg, k * 284, ref)) {
		printf("FAIL: python3 hmac reference did not run\n");
		failures++;
		return 0;
	}
	return !memcmp(ours, ref, 32) &&
	       !memcmp(ours, frames + (k - 1) * FR + 196, 32);
}

static void sign(uint8_t *frames, uint32_t k)
{
	uint8_t msg[64 * 284];
	uint32_t i;

	for (i = 0; i < k; i++)
		memcpy(msg + i * 284, frames + i * FR + 228, 284);
	rpmb_emu_hmac_sha256(key, sizeof(key), msg, k * 284,
			     frames + (k - 1) * FR + 196);
}

static int unhex(uint8_t *out, const char *s)
{
	unsigned int b;
	int n = 0;

	for (; s[0] && s[1]; s += 2, n++) {
		if (sscanf(s, "%2x", &b) != 1)
			return -1;
		out[n] = (uint8_t)b;
	}
	return n;
}

static void test_kat(void)
{
	static const struct {
		uint8_t keyb;
		size_t keylen;
		const char *msg, *mac;
	} v[] = {
		/* RFC 4231 test case 1 */
		{ 0x0b, 20, "Hi There", "b0344c61d8db38535ca8afceaf0bf12b"
		  "881dc200c9833da726e9376c2e32cff7" },
		/* test case 6: a key longer than the block */
		{ 0xaa, 131, "Test Using Larger Than Block-Size Key - Hash "
		  "Key First", "60e431591ee0b67f0d8a26aacbf5b77f"
		  "8e0bc6213728c5140546040f0ee37f54" },
	};
	uint8_t k[131], want[32], got[32];
	size_t i;

	printf("HMAC-SHA256 known answers (RFC 4231 1, 2, 6)\n");
	rpmb_emu_hmac_sha256((const uint8_t *)"Jefe", 4,
			     (const uint8_t *)"what do ya want for nothing?",
			     28, got);
	unhex(want, "5bdcc146bf60754e6a042426089575c7"
		    "5a003f089d2739839dec58b964ec3843");
	CHECK(!memcmp(got, want, 32), "RFC 4231 test case 2");
	for (i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
		memset(k, v[i].keyb, v[i].keylen);
		rpmb_emu_hmac_sha256(k, v[i].keylen,
				     (const uint8_t *)v[i].msg,
				     strlen(v[i].msg), got);
		unhex(want, v[i].mac);
		CHECK(!memcmp(got, want, 32), "RFC 4231 vector %zu", i);
	}
}

static void test_init(void)
{
	uint32_t len;

	printf("0x101 init, 0x104, unknown command\n");
	memset(sb, 0, SB_LEN);
	setw(0, 0x101);
	setw(4, 1);
	len = serve();
	CHECK(len == 20 && w(0) == 0x101 && w(4) == 1 && w(8) == 0 &&
	      w(12) == 8192 && w(16) == 64, "init sub 1");
	setw(0, 0x101);
	setw(4, 0);
	len = serve();
	CHECK(len == 20 && w(4) == 1 && w(8) == 0xffffffffu && w(12) == 0 &&
	      w(16) == 0, "init sub 0");
	setw(0, 0x101);
	setw(4, 2);
	len = serve();
	CHECK(len == 40 && w(4) == 2 && w(8) == 0 && w(12) == 8192 &&
	      w(16) == 64 && w(20) == 9 && w(24) == 0 && w(36) == 0,
	      "init sub 2");
	setw(0, 0x104);
	setw(4, 0x200);
	len = serve();
	CHECK(len == 16 && w(0) == 0x104 && w(4) == 0xffffffffu &&
	      w(8) == 0 && w(12) == 16, "0x104");
	setw(0, 0x1ff);
	len = serve();
	CHECK(len == 20 && w(0) == 0x1ff && w(4) == 0xfffffff9u &&
	      w(8) == 0 && w(12) == 20, "unknown command");
}

/* A 0x102 read of n frames: one request frame at +0x18. */
static uint8_t *read_req(uint32_t n, uint32_t type, uint32_t addr)
{
	uint8_t *f = sb + 0x18;
	int i;

	memset(sb, 0, SB_LEN);
	setw(0, 0x102);
	setw(4, n);
	setw(8, 0x200);
	setw(12, 0x18);
	for (i = 0; i < 16; i++)
		f[484 + i] = (uint8_t)(0xa0 + i);
	p16(f, 504, addr);
	p16(f, 510, type);
	CHECK(serve() == 20 && w(4) == 0 && w(8) == n * FR && w(12) == 20,
	      "read header");
	return sb + 0x14;
}

static int nonce_ok(const uint8_t *f)
{
	int i;

	for (i = 0; i < 16; i++)
		if (f[484 + i] != 0xa0 + i)
			return 0;
	return 1;
}

static void test_read_counter(uint32_t want_result, uint32_t want_ctr)
{
	uint8_t *f = read_req(1, 0x0002, 0);

	CHECK(g16(f, 510) == 0x0200 && g16(f, 508) == want_result &&
	      g32(f, 500) == want_ctr && nonce_ok(f),
	      "read counter: result 0x%04x counter %u", g16(f, 508),
	      g32(f, 500));
	if (want_result == 0x0007) {
		static const uint8_t zero[32];

		CHECK(!memcmp(f + 196, zero, 32), "no MAC without a key");
	} else {
		CHECK(frames_mac_ok(f, 1), "read counter MAC");
	}
}

/* A 0x103 write: frames already at +0x18, w4 per transfer. */
static uint8_t *write_req(uint32_t n, uint32_t w4, int want_status)
{
	setw(0, 0x103);
	setw(4, n);
	setw(8, 0);
	setw(12, 0x18);
	setw(16, 0);
	setw(20, w4);
	CHECK(serve() == 20 && w(12) == 20, "write reply length");
	if (want_status) {
		CHECK(w(4) == 0xffffffffu && w(8) == 0, "write refused");
		return NULL;
	}
	CHECK(w(4) == 0 && w(8) == FR, "write header");
	return sb + 0x14;
}

static void program_key(uint32_t want)
{
	uint8_t *f = sb + 0x18, *r;

	memset(sb, 0, SB_LEN);
	memcpy(f + 196, key, sizeof(key));
	p16(f, 510, 0x0001);
	r = write_req(1, 1, 0);
	CHECK(g16(r, 510) == 0x0100 && g16(r, 508) == want &&
	      g32(r, 500) == 0 && g16(r, 504) == 0,
	      "program key: result 0x%04x", g16(r, 508));
}

/* Two frames of data at addr, with the given counter; bad_mac flips a bit. */
static uint8_t *auth_write(uint32_t addr, uint32_t ctr, int bad_mac)
{
	uint8_t *f = sb + 0x18;
	uint32_t i, j;

	memset(sb, 0, SB_LEN);
	for (i = 0; i < 2; i++) {
		uint8_t *fi = f + i * FR;

		for (j = 0; j < 256; j++)
			fi[228 + j] = (uint8_t)(i * 0x40 + j);
		p32(fi, 500, ctr);
		p16(fi, 504, addr);
		p16(fi, 506, 2);
		p16(fi, 510, 0x0003);
	}
	sign(f, 2);
	if (bad_mac)
		f[FR + 196] ^= 1;
	return write_req(2, 2, 0);
}

static void check_write(const uint8_t *r, uint32_t want, uint32_t ctr,
			uint32_t addr)
{
	CHECK(g16(r, 510) == 0x0300 && g16(r, 508) == want &&
	      g32(r, 500) == ctr && g16(r, 504) == addr && g16(r, 506) == 0,
	      "auth write: result 0x%04x counter %u", g16(r, 508),
	      g32(r, 500));
	CHECK(frames_mac_ok(r, 1), "auth write result MAC");
}

static void test_auth_read(void)
{
	uint8_t *f = read_req(6, 0x0004, 0x10);
	uint32_t i, j, bad = 0;

	for (i = 0; i < 6; i++) {
		const uint8_t *fi = f + i * FR;

		bad |= g16(fi, 510) != 0x0400 || g16(fi, 508) != 0 ||
		       g16(fi, 504) != 0x10 || g16(fi, 506) != 6 ||
		       g32(fi, 500) != 0 || !nonce_ok(fi);
		for (j = 0; j < 256; j++)
			bad |= fi[228 + j] !=
			       (i < 2 ? (uint8_t)(i * 0x40 + j) : 0);
	}
	CHECK(!bad, "auth read: frames and data");
	CHECK(frames_mac_ok(f, 6), "auth read MAC over 6 frames");
	f = read_req(6, 0x0004, 16380);
	CHECK(g16(f, 508) == 0x0004 && g16(f + 5 * FR, 508) == 0x0004,
	      "out-of-range read: result 0x%04x", g16(f, 508));
}

static void test_files(const char *dir)
{
	struct dirent *de;
	struct stat st;
	char path[512];
	int other = 0, n = 0;
	DIR *d = opendir(dir);

	if (!d) {
		CHECK(0, "opendir");
		return;
	}
	while ((de = readdir(d))) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		n++;
		if (strcmp(de->d_name, "rpmb.img") && strcmp(de->d_name, "state"))
			other++;
	}
	closedir(d);
	CHECK(n == 2 && !other, "state dir holds only rpmb.img and state");
	snprintf(path, sizeof(path), "%s/rpmb.img", dir);
	CHECK(!stat(path, &st) && S_ISREG(st.st_mode) &&
	      st.st_size == 4 << 20 && (st.st_mode & 0777) == 0600,
	      "rpmb.img 4 MiB, 0600");
}

static void cleanup(const char *dir)
{
	char path[512];

	snprintf(path, sizeof(path), "%s/rpmb.img", dir);
	unlink(path);
	snprintf(path, sizeof(path), "%s/state", dir);
	unlink(path);
	rmdir(dir);
}

int main(void)
{
	char dir[] = "/tmp/rpmb-emu-test.XXXXXX", err[256];
	unsigned int i;
	uint8_t *r;

	for (i = 0; i < sizeof(key); i++)
		key[i] = (uint8_t)(i * 7 + 1);
	test_kat();
	if (!mkdtemp(dir)) {
		perror("mkdtemp");
		return 1;
	}
	CHECK(rpmb_emu_open(&emu, "/nonexistent-rpmb-emu", err,
			    sizeof(err)) == -1, "missing dir refused");
	if (rpmb_emu_open(&emu, dir, err, sizeof(err))) {
		printf("FAIL: open: %s\n", err);
		return 1;
	}
	test_init();

	printf("before the key\n");
	test_read_counter(0x0007, 0);
	r = read_req(6, 0x0004, 0);
	CHECK(g16(r, 508) == 0x0007 && g16(r, 510) == 0x0400, "read, no key");
	r = auth_write(0x10, 0, 0);
	CHECK(g16(r, 508) == 0x0007, "write, no key");

	printf("program the key\n");
	program_key(0x0000);
	program_key(0x0001);
	test_read_counter(0x0000, 0);

	printf("authenticated writes\n");
	check_write(auth_write(0x10, 0, 0), 0x0000, 1, 0x10);
	check_write(auth_write(0x10, 0, 0), 0x0003, 1, 0x10);
	check_write(auth_write(0x10, 1, 1), 0x0002, 1, 0x10);
	check_write(auth_write(16383, 1, 0), 0x0004, 1, 16383);
	memset(sb, 0, SB_LEN);
	write_req(4, 3, 1);
	write_req(2, 65, 1);
	write_req(2, 0, 1);
	test_read_counter(0x0000, 1);

	printf("authenticated reads\n");
	test_auth_read();
	r = read_req(1, 0x0005, 0);
	CHECK(g16(r, 510) == 0x0500 && g16(r, 508) == 0x0001,
	      "unknown read request");

	printf("state survives a reopen\n");
	rpmb_emu_close(&emu);
	CHECK(!rpmb_emu_open(&emu, dir, err, sizeof(err)) &&
	      emu.st.key_programmed == 1 && emu.st.write_counter == 1,
	      "reopen: %s", err);
	test_auth_read();
	rpmb_emu_close(&emu);
	test_files(dir);
	cleanup(dir);

	if (failures)
		printf("rpmb-emu-test: %d FAILED\n", failures);
	else
		printf("rpmb-emu-test: ok\n");
	return failures != 0;
}
