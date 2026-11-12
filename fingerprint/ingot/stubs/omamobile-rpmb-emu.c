// SPDX-License-Identifier: MIT
/*
 * omamobile-rpmb-emu: the RPMB the listener serves, kept in two regular
 * files under a state directory (see omamobile-rpmb-emu.h and the header
 * comment of omamobile-listener-stub.c). Frames follow JEDEC RPMB: 512
 * bytes, big-endian fields, HMAC-SHA256 over bytes 228..511 of every frame
 * of a transfer. The listener header words are little-endian (aarch64).
 *
 * Built into librpmb.so (#included by the listener stub, one link unit) and
 * into the host test, so it uses only libc: no OpenSSL in the chroot.
 */

#include "omamobile-rpmb-emu.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- SHA-256 (FIPS 180-4) and HMAC (RFC 2104) ---- */

struct sha256 {
	uint32_t h[8];
	uint8_t buf[64];
	uint64_t len;
	size_t fill;
};

static const uint32_t sha256_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t ror(uint32_t x, unsigned int n)
{
	return (x >> n) | (x << (32 - n));
}

static void sha256_block(struct sha256 *s, const uint8_t *p)
{
	uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 |
		       (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
	for (i = 16; i < 64; i++)
		w[i] = w[i - 16] + w[i - 7] +
		       (ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ w[i - 15] >> 3) +
		       (ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ w[i - 2] >> 10);
	a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
	e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
	for (i = 0; i < 64; i++) {
		t1 = h + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) +
		     ((e & f) ^ (~e & g)) + sha256_k[i] + w[i];
		t2 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) +
		     ((a & b) ^ (a & c) ^ (b & c));
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
	s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha256_init(struct sha256 *s)
{
	static const uint32_t iv[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	};

	memcpy(s->h, iv, sizeof(iv));
	s->len = 0;
	s->fill = 0;
}

static void sha256_update(struct sha256 *s, const uint8_t *p, size_t n)
{
	s->len += n;
	while (n) {
		size_t take = 64 - s->fill;

		if (take > n)
			take = n;
		memcpy(s->buf + s->fill, p, take);
		s->fill += take;
		p += take;
		n -= take;
		if (s->fill == 64) {
			sha256_block(s, s->buf);
			s->fill = 0;
		}
	}
}

static void sha256_final(struct sha256 *s, uint8_t out[32])
{
	uint64_t bits = s->len * 8;
	uint8_t pad[72] = { 0x80 };
	size_t padlen = (s->fill < 56 ? 56 : 120) - s->fill;
	int i;

	for (i = 0; i < 8; i++)
		pad[padlen + i] = (uint8_t)(bits >> (56 - 8 * i));
	sha256_update(s, pad, padlen + 8);
	for (i = 0; i < 8; i++) {
		out[4 * i] = (uint8_t)(s->h[i] >> 24);
		out[4 * i + 1] = (uint8_t)(s->h[i] >> 16);
		out[4 * i + 2] = (uint8_t)(s->h[i] >> 8);
		out[4 * i + 3] = (uint8_t)s->h[i];
	}
}

struct hmac {
	struct sha256 inner;
	uint8_t opad[64];
};

static void hmac_init(struct hmac *m, const uint8_t *key, size_t keylen)
{
	uint8_t k[64] = { 0 }, ipad[64];
	int i;

	if (keylen > 64) {
		sha256_init(&m->inner);
		sha256_update(&m->inner, key, keylen);
		sha256_final(&m->inner, k);
	} else {
		memcpy(k, key, keylen);
	}
	for (i = 0; i < 64; i++) {
		ipad[i] = k[i] ^ 0x36;
		m->opad[i] = k[i] ^ 0x5c;
	}
	sha256_init(&m->inner);
	sha256_update(&m->inner, ipad, sizeof(ipad));
	memset(k, 0, sizeof(k));
	memset(ipad, 0, sizeof(ipad));
}

static void hmac_final(struct hmac *m, uint8_t out[32])
{
	struct sha256 outer;
	uint8_t ih[32];

	sha256_final(&m->inner, ih);
	sha256_init(&outer);
	sha256_update(&outer, m->opad, sizeof(m->opad));
	sha256_update(&outer, ih, sizeof(ih));
	sha256_final(&outer, out);
	memset(m, 0, sizeof(*m));
}

void rpmb_emu_hmac_sha256(const uint8_t *key, size_t keylen,
			  const uint8_t *msg, size_t len,
			  uint8_t out[RPMB_EMU_SHA256_LEN])
{
	struct hmac m;

	hmac_init(&m, key, keylen);
	sha256_update(&m.inner, msg, len);
	hmac_final(&m, out);
}

/* A MAC compare must not tell TrustZone (or anyone timing it) how far it got. */
static int mac_equal(const uint8_t *a, const uint8_t *b)
{
	uint8_t diff = 0;
	unsigned int i;

	for (i = 0; i < RPMB_EMU_SHA256_LEN; i++)
		diff |= a[i] ^ b[i];
	return diff == 0;
}

/* ---- JEDEC frames ---- */

#define F_MAC		196u
#define F_DATA		228u
#define F_NONCE		484u
#define F_COUNTER	500u
#define F_ADDR		504u
#define F_COUNT		506u
#define F_RESULT	508u
#define F_TYPE		510u
#define F_MAC_SPAN	(RPMB_EMU_FRAME - F_DATA)	/* 284 */

#define REQ_PROGRAM_KEY	0x0001u
#define REQ_READ_CTR	0x0002u
#define REQ_AUTH_WRITE	0x0003u
#define REQ_AUTH_READ	0x0004u

#define RES_OK		0x0000u
#define RES_GENERAL	0x0001u
#define RES_AUTH	0x0002u
#define RES_COUNTER	0x0003u
#define RES_ADDRESS	0x0004u
#define RES_WRITE	0x0005u
#define RES_READ	0x0006u
#define RES_NO_KEY	0x0007u
#define RES_EXPIRED	0x0080u

/* Transfers per read: 0x6400 bytes hold 49 frames, so one is all we see. */
#define MAX_TX		4u

static uint16_t be16(const uint8_t *p)
{
	return (uint16_t)(p[0] << 8 | p[1]);
}

static uint32_t be32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | p[3];
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

/* The header words: native little-endian, maybe unaligned. */
static uint32_t hdr_get(const unsigned char *sb, size_t off)
{
	uint32_t v;

	memcpy(&v, sb + off, sizeof(v));
	return v;
}

static void hdr_set(unsigned char *sb, size_t off, uint32_t v)
{
	memcpy(sb + off, &v, sizeof(v));
}

/* MAC of k consecutive frames: bytes 228..511 of each, concatenated. */
static void frames_mac(const struct rpmb_emu *e, const uint8_t *frames,
		       uint32_t k, uint8_t out[32])
{
	struct hmac m;
	uint32_t i;

	hmac_init(&m, e->st.key, RPMB_EMU_KEY);
	for (i = 0; i < k; i++)
		sha256_update(&m.inner, frames + i * RPMB_EMU_FRAME + F_DATA,
			      F_MAC_SPAN);
	hmac_final(&m, out);
}

/* ---- the log line ---- */

struct desc {
	char *buf;
	size_t len, pos;
};

__attribute__((format(printf, 2, 3)))
static void add(struct desc *d, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (!d->len || d->pos >= d->len - 1)
		return;
	va_start(ap, fmt);
	n = vsnprintf(d->buf + d->pos, d->len - d->pos, fmt, ap);
	va_end(ap);
	if (n > 0)
		d->pos += (size_t)n < d->len - d->pos ? (size_t)n
						      : d->len - d->pos - 1;
}

/* Only the nonce's first 4 bytes: enough to match a request to its reply. */
static void add_nonce(struct desc *d, const uint8_t *frame)
{
	const uint8_t *n = frame + F_NONCE;

	add(d, "nonce=%02x%02x%02x%02x..", n[0], n[1], n[2], n[3]);
}

/* ---- state files ---- */

static int store_state(struct rpmb_emu *e, const struct rpmb_emu_state *st)
{
	if (pwrite(e->state_fd, st, sizeof(*st), 0) != (ssize_t)sizeof(*st))
		return -1;
	if (fdatasync(e->state_fd))
		return -1;
	e->st = *st;
	return 0;
}

__attribute__((format(printf, 3, 4)))
static int fail(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
	return -1;
}

/* O_NOFOLLOW and the S_ISREG check: a symlink or a node planted in the
 * state directory is refused, so only a regular file is ever opened. */
static int open_regular(const char *dir, const char *name, off_t *size,
			char *err, size_t errlen)
{
	char path[512];
	struct stat st;
	int fd, n;

	n = snprintf(path, sizeof(path), "%s/%s", dir, name);
	if (n < 0 || (size_t)n >= sizeof(path))
		return fail(err, errlen, "state path too long");
	fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0)
		return fail(err, errlen, "open %s: %s", path, strerror(errno));
	if (fstat(fd, &st) || !S_ISREG(st.st_mode)) {
		close(fd);
		return fail(err, errlen, "%s is not a regular file", path);
	}
	*size = st.st_size;
	return fd;
}

static int load_state(struct rpmb_emu *e, off_t size, char *err,
		      size_t errlen)
{
	struct rpmb_emu_state st;

	if (size == 0) {
		memset(&st, 0, sizeof(st));
		st.magic = RPMB_EMU_STATE_MAGIC;
		st.version = RPMB_EMU_STATE_VERSION;
		if (store_state(e, &st))
			return fail(err, errlen, "state: create: %s",
				    strerror(errno));
		return 0;
	}
	if (size != (off_t)sizeof(st) ||
	    pread(e->state_fd, &st, sizeof(st), 0) != (ssize_t)sizeof(st))
		return fail(err, errlen, "state: size %lld, want %zu",
			    (long long)size, sizeof(st));
	if (st.magic != RPMB_EMU_STATE_MAGIC ||
	    st.version != RPMB_EMU_STATE_VERSION || st.key_programmed > 1)
		return fail(err, errlen, "state: bad magic/version/flag");
	e->st = st;
	return 0;
}

int rpmb_emu_open(struct rpmb_emu *e, const char *dir, char *err,
		  size_t errlen)
{
	const off_t img_size = (off_t)RPMB_EMU_BLOCKS * RPMB_EMU_BLOCK;
	struct stat st;
	off_t size;

	memset(e, 0, sizeof(*e));
	e->img_fd = e->state_fd = -1;
	/* stat, not mkdir: the stage tool creates it root:root 0700. */
	if (stat(dir, &st) || !S_ISDIR(st.st_mode))
		return fail(err, errlen, "state directory %s missing", dir);
	e->img_fd = open_regular(dir, "rpmb.img", &size, err, errlen);
	if (e->img_fd < 0)
		goto out;
	if (size == 0 && ftruncate(e->img_fd, img_size)) {
		fail(err, errlen, "rpmb.img: ftruncate: %s", strerror(errno));
		goto out;
	}
	if (size != 0 && size != img_size) {
		fail(err, errlen, "rpmb.img: size %lld, want %lld",
		     (long long)size, (long long)img_size);
		goto out;
	}
	e->state_fd = open_regular(dir, "state", &size, err, errlen);
	if (e->state_fd < 0 || load_state(e, size, err, errlen))
		goto out;
	return 0;
out:
	rpmb_emu_close(e);
	return -1;
}

void rpmb_emu_close(struct rpmb_emu *e)
{
	if (e->img_fd >= 0)
		close(e->img_fd);
	if (e->state_fd >= 0)
		close(e->state_fd);
	e->img_fd = e->state_fd = -1;
	memset(&e->st, 0, sizeof(e->st));
}

/* ---- 0x102 read: one request frame in, k reply frames out ---- */

static void read_counter(struct rpmb_emu *e, const uint8_t *req,
			 uint8_t *out, struct desc *d)
{
	int key = e->st.key_programmed;
	uint32_t result = key ? RES_OK : RES_NO_KEY;
	uint32_t ctr = key ? e->st.write_counter : 0;

	put16(out + F_TYPE, REQ_READ_CTR << 8);
	memcpy(out + F_NONCE, req + F_NONCE, 16);
	put32(out + F_COUNTER, ctr);
	put16(out + F_RESULT, result);
	if (key)
		frames_mac(e, out, 1, out + F_MAC);
	add(d, "read-counter ");
	add_nonce(d, req);
	add(d, " -> result 0x%04x counter %u", result, ctr);
}

static uint32_t read_blocks(struct rpmb_emu *e, uint32_t addr, uint32_t k,
			    uint8_t *out)
{
	uint32_t i;

	for (i = 0; i < k; i++) {
		off_t off = (off_t)(addr + i) * RPMB_EMU_BLOCK;
		uint8_t *data = out + i * RPMB_EMU_FRAME + F_DATA;

		if (pread(e->img_fd, data, RPMB_EMU_BLOCK, off) !=
		    (ssize_t)RPMB_EMU_BLOCK) {
			memset(out, 0, (size_t)k * RPMB_EMU_FRAME);
			return RES_READ;
		}
	}
	return RES_OK;
}

static void auth_read(struct rpmb_emu *e, const uint8_t *req, uint8_t *out,
		      uint32_t k, struct desc *d)
{
	uint32_t addr = be16(req + F_ADDR), result, i;
	int key = e->st.key_programmed;

	if (!key && e->probe_unauth_ok)
		result = RES_OK;	/* the probe: an OK nobody can verify */
	else if (!key)
		result = RES_NO_KEY;
	else if (addr + k > RPMB_EMU_BLOCKS)
		result = RES_ADDRESS;
	else
		result = read_blocks(e, addr, k, out);
	for (i = 0; i < k; i++) {
		uint8_t *f = out + i * RPMB_EMU_FRAME;

		put16(f + F_TYPE, REQ_AUTH_READ << 8);
		memcpy(f + F_NONCE, req + F_NONCE, 16);
		put16(f + F_ADDR, addr);
		put16(f + F_COUNT, k);
		put16(f + F_RESULT, result);
	}
	if (key)
		frames_mac(e, out, k, out + (k - 1) * RPMB_EMU_FRAME + F_MAC);
	add(d, "auth-read addr 0x%04x k %u ", addr, k);
	add_nonce(d, req);
	add(d, " -> result 0x%04x%s", result,
	    !key && e->probe_unauth_ok ? " (probe: no key, no MAC)" : "");
}

static void unknown_req(uint32_t type, uint8_t *out, uint32_t k,
			struct desc *d)
{
	uint32_t i;

	for (i = 0; i < k; i++) {
		put16(out + i * RPMB_EMU_FRAME + F_TYPE, type << 8);
		put16(out + i * RPMB_EMU_FRAME + F_RESULT, RES_GENERAL);
	}
	add(d, "request type 0x%04x unknown -> result 0x%04x", type,
	    RES_GENERAL);
}

static void read_tx(struct rpmb_emu *e, const uint8_t *req, uint8_t *out,
		    uint32_t k, struct desc *d)
{
	uint32_t type = be16(req + F_TYPE);

	memset(out, 0, (size_t)k * RPMB_EMU_FRAME);
	if (type == REQ_READ_CTR)
		read_counter(e, req, out, d);
	else if (type == REQ_AUTH_READ)
		auth_read(e, req, out, k, d);
	else
		unknown_req(type, out, k, d);
}

static uint32_t header_reply(unsigned char *sb, uint32_t status,
			     uint32_t moved)
{
	hdr_set(sb, 4, status);
	hdr_set(sb, 8, moved);
	hdr_set(sb, 0xc, 20);
	return 20;
}

static uint32_t serve_read(struct rpmb_emu *e, unsigned char *sb,
			   uint32_t sb_len, uint32_t n, struct desc *d)
{
	uint8_t req[MAX_TX][RPMB_EMU_FRAME];
	uint32_t ntx = (n + RPMB_EMU_FPT - 1) / RPMB_EMU_FPT, t;

	if (n == 0 || n > (sb_len - RPMB_EMU_HDR) / RPMB_EMU_FRAME ||
	    ntx > MAX_TX ||
	    RPMB_EMU_REQ + ntx * RPMB_EMU_FRAME > sb_len) {
		add(d, "frame count does not fit the buffer -> status -1");
		return header_reply(sb, 0xffffffffu, 0);
	}
	/* The replies overwrite the request frames: copy them first. */
	for (t = 0; t < ntx; t++)
		memcpy(req[t], sb + RPMB_EMU_REQ + t * RPMB_EMU_FRAME,
		       RPMB_EMU_FRAME);
	for (t = 0; t < ntx; t++) {
		uint32_t k = n - t * RPMB_EMU_FPT;

		if (k > RPMB_EMU_FPT)
			k = RPMB_EMU_FPT;
		if (t)
			add(d, "; ");
		read_tx(e, req[t], sb + RPMB_EMU_HDR +
			t * RPMB_EMU_FPT * RPMB_EMU_FRAME, k, d);
	}
	return header_reply(sb, 0, n * RPMB_EMU_FRAME);
}

/* ---- 0x103 write: w4 frames in, one result frame out ---- */

static uint32_t program_key(struct rpmb_emu *e, const uint8_t *frames,
			    uint32_t w4, struct desc *d)
{
	struct rpmb_emu_state st = e->st;
	uint32_t result;
	const char *why;

	if (w4 != 1) {
		result = RES_GENERAL;
		why = "not one frame";
	} else if (e->st.key_programmed) {
		result = RES_GENERAL;
		why = "a key cannot be reprogrammed";
	} else {
		memcpy(st.key, frames + F_MAC, RPMB_EMU_KEY);
		st.key_programmed = 1;
		st.write_counter = 0;
		result = store_state(e, &st) ? RES_WRITE : RES_OK;
		why = result ? "state write failed" : "key stored";
	}
	memset(&st, 0, sizeof(st));
	add(d, "program-key -> result 0x%04x (%s)", result, why);
	return result;
}

static uint32_t write_blocks(struct rpmb_emu *e, const uint8_t *frames,
			     uint32_t addr, uint32_t w4)
{
	struct rpmb_emu_state st = e->st;
	uint32_t i;

	for (i = 0; i < w4; i++) {
		off_t off = (off_t)(addr + i) * RPMB_EMU_BLOCK;

		if (pwrite(e->img_fd, frames + i * RPMB_EMU_FRAME + F_DATA,
			   RPMB_EMU_BLOCK, off) != (ssize_t)RPMB_EMU_BLOCK)
			return RES_WRITE;
	}
	if (fdatasync(e->img_fd))
		return RES_WRITE;
	st.write_counter++;
	return store_state(e, &st) ? RES_WRITE : RES_OK;
}

static uint32_t auth_write(struct rpmb_emu *e, const uint8_t *frames,
			   uint32_t w4, uint8_t *res, struct desc *d)
{
	const uint8_t *last = frames + (w4 - 1) * RPMB_EMU_FRAME;
	uint32_t addr = be16(frames + F_ADDR);
	uint32_t ctr = be32(frames + F_COUNTER);
	uint32_t result;
	uint8_t mac[32];

	if (!e->st.key_programmed) {
		result = RES_NO_KEY;
	} else {
		frames_mac(e, frames, w4, mac);
		if (!mac_equal(mac, last + F_MAC))
			result = RES_AUTH;
		else if (e->st.write_counter == 0xffffffffu)
			result = RES_COUNTER | RES_EXPIRED;
		else if (ctr != e->st.write_counter)
			result = RES_COUNTER;
		else if (addr + w4 > RPMB_EMU_BLOCKS)
			result = RES_ADDRESS;
		else
			result = write_blocks(e, frames, addr, w4);
		memset(mac, 0, sizeof(mac));
	}
	put32(res + F_COUNTER, e->st.write_counter);
	put16(res + F_ADDR, addr);
	add(d, "auth-write addr 0x%04x k %u counter %u -> result 0x%04x "
	    "counter %u", addr, w4, ctr, result, e->st.write_counter);
	return result;
}

static void write_tx(struct rpmb_emu *e, const uint8_t *frames,
		     uint32_t w4, uint8_t *res, struct desc *d)
{
	uint32_t type = be16(frames + F_TYPE), result;

	memset(res, 0, RPMB_EMU_FRAME);
	if (type == REQ_PROGRAM_KEY) {
		result = program_key(e, frames, w4, d);
	} else if (type == REQ_AUTH_WRITE) {
		result = auth_write(e, frames, w4, res, d);
	} else {
		unknown_req(type, res, 1, d);
		return;
	}
	put16(res + F_TYPE, type << 8);
	put16(res + F_RESULT, result);
	/* The program-key reply has no MAC: the key is not proven yet. */
	if (type == REQ_AUTH_WRITE && e->st.key_programmed)
		frames_mac(e, res, 1, res + F_MAC);
}

static uint32_t serve_write(struct rpmb_emu *e, unsigned char *sb,
			    uint32_t sb_len, uint32_t n, struct desc *d)
{
	uint32_t w4 = hdr_get(sb, 0x14), t;
	uint8_t res[RPMB_EMU_FRAME];

	if (w4 == 0 || w4 > RPMB_EMU_FPT || n == 0 || n % w4 ||
	    n > (sb_len - RPMB_EMU_REQ) / RPMB_EMU_FRAME) {
		add(d, "bad frames per transfer -> status -1");
		return header_reply(sb, 0xffffffffu, 0);
	}
	/* Transfer t+1's frames start past the result frame, so writing
	 * each result at +0x14 never clobbers a frame still to be read. */
	for (t = 0; t < n / w4; t++) {
		if (t)
			add(d, "; ");
		write_tx(e, sb + RPMB_EMU_REQ + t * w4 * RPMB_EMU_FRAME, w4,
			 res, d);
		memcpy(sb + RPMB_EMU_HDR, res, sizeof(res));
	}
	return header_reply(sb, 0, RPMB_EMU_FRAME);
}

/* ---- 0x101, 0x104, unknown ---- */

static uint32_t put_words(unsigned char *sb, const uint32_t *w, size_t n)
{
	memcpy(sb, w, n * sizeof(*w));
	return (uint32_t)(n * sizeof(*w));
}

static uint32_t serve_init(unsigned char *sb, uint32_t sub, struct desc *d)
{
	const uint32_t one[5] = { 0x101, 1, 0, RPMB_EMU_SECTORS,
				  RPMB_EMU_FPT };
	const uint32_t zero[5] = { 0x101, 1, 0xffffffffu, 0, 0 };
	const uint32_t other[10] = { 0x101, 2, 0, RPMB_EMU_SECTORS,
				     RPMB_EMU_FPT, RPMB_EMU_TYPE };

	if (sub == 0) {
		add(d, "init sub 0 -> constant {1, -1, 0, 0}");
		return put_words(sb, zero, 5);
	}
	add(d, "init sub %u -> size %u fpt %u type %u", sub, RPMB_EMU_SECTORS,
	    RPMB_EMU_FPT, RPMB_EMU_TYPE);
	return sub == 1 ? put_words(sb, one, 5) : put_words(sb, other, 10);
}

uint32_t rpmb_emu_serve(struct rpmb_emu *e, unsigned char *sb,
			uint32_t sb_len, char *desc, size_t desclen)
{
	struct desc d = { desc, desclen, 0 };
	uint32_t cmd = hdr_get(sb, 0), n = hdr_get(sb, 4);
	uint32_t per_tx = cmd == 0x102 ? RPMB_EMU_FPT
			: cmd == 0x103 ? hdr_get(sb, 0x14) : 0;

	if (desclen)
		desc[0] = 0;
	add(&d, "command 0x%x, frames %u (%u per tx): ", cmd, n, per_tx);
	switch (cmd) {
	case 0x101:
		return serve_init(sb, n, &d);
	case 0x102:
		return serve_read(e, sb, sb_len, n, &d);
	case 0x103:
		return serve_write(e, sb, sb_len, n, &d);
	case 0x104: {
		const uint32_t none[4] = { 0x104, 0xffffffffu, 0, 16 };

		add(&d, "partition config -> not found");
		return put_words(sb, none, 4);
	}
	default: {
		const uint32_t unk[5] = { cmd, 0xfffffff9u, 0, 20 };

		add(&d, "unknown command -> status 0xfffffff9");
		return put_words(sb, unk, 5);
	}
	}
}
