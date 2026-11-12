// SPDX-License-Identifier: MIT
/*
 * omamobile-rpmb-pt: the RPMB pass-through the listener serves (see
 * omamobile-rpmb-pt.h and the header comment of omamobile-listener-stub.c).
 *
 * What the vendor's listener does with each command, mirrored here:
 *   0x102 read   per transfer: SECURITY PROTOCOL OUT of ONE request frame,
 *                then SECURITY PROTOCOL IN of up to fpt reply frames, which
 *                go to the shared buffer at +0x14 (one after the other for
 *                several transfers);
 *   0x103 write  per transfer: SECURITY PROTOCOL OUT of w4 data frames,
 *                SECURITY PROTOCOL OUT of the constant RESULT READ request
 *                frame, SECURITY PROTOCOL IN of one result frame to +0x14;
 *   0x101 init   the device's size and frames per transfer;
 *   0x104 cfg    "not found" (no rpmb_sec_parti.cfg here).
 * The CDBs are the UFS RPMB ones: opcode 0xb5 (OUT) or 0xa2 (IN), security
 * protocol 0xec, protocol specific 0x0001, the length in bytes.
 *
 * What it refuses, before any I/O: a request frame whose type is PROGRAM
 * KEY (0x0001), on either path, whoever asks; every 0x103 write while
 * writes are off; a header whose frame counts do not fit the buffer. A
 * refusal is status -1 in the header with the reply area untouched: no
 * frame is ever made up.
 *
 * Built into librpmb.so (#included by the listener stub, one link unit) and
 * into the host test, so it uses only libc.
 */

#include "omamobile-rpmb-pt.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/bsg.h>
#ifndef SG_IO
#define SG_IO 0x2285
#endif
#endif

/* Frame fields (big-endian, byte offsets) */
#define F_MAC		196u
#define F_DATA		228u
#define F_NONCE		484u
#define F_COUNTER	500u
#define F_ADDR		504u
#define F_COUNT		506u
#define F_RESULT	508u
#define F_TYPE		510u

#define STATUS_REFUSED	0xffffffffu	/* -1: the vendor's generic failure */
#define STATUS_SCSI	0xfffffffbu	/* -5: a SCSI level error */
#define STATUS_UNKNOWN	0xfffffff9u	/* -7: unknown command (vendor) */

/* ---- small helpers ---- */

static uint32_t hdr_get(const unsigned char *sb, uint32_t off)
{
	uint32_t v;

	memcpy(&v, sb + off, sizeof(v));
	return v;
}

static void hdr_set(unsigned char *sb, uint32_t off, uint32_t v)
{
	memcpy(sb + off, &v, sizeof(v));
}

static uint32_t be16(const uint8_t *p)
{
	return (uint32_t)p[0] << 8 | p[1];
}

static uint32_t be32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | p[3];
}

struct desc {
	char *buf;
	size_t len;
	size_t at;
};

__attribute__((format(printf, 2, 3)))
static void add(struct desc *d, const char *fmt, ...)
{
	va_list ap;
	int n;

	if (!d->buf || d->at >= d->len)
		return;
	va_start(ap, fmt);
	n = vsnprintf(d->buf + d->at, d->len - d->at, fmt, ap);
	va_end(ap);
	if (n > 0)
		d->at += (size_t)n < d->len - d->at ? (size_t)n
						    : d->len - d->at - 1;
}

/* The first 4 bytes of the nonce: random, not secret, enough to match a
 * reply to its request in the log. */
static void add_nonce(struct desc *d, const uint8_t *f)
{
	add(d, "nonce=%02x%02x%02x%02x..", f[F_NONCE], f[F_NONCE + 1],
	    f[F_NONCE + 2], f[F_NONCE + 3]);
}

static const char *type_name(uint32_t type)
{
	switch (type) {
	case RPMB_PT_REQ_PROGRAM_KEY: return "program-key";
	case RPMB_PT_REQ_READ_CTR: return "read-counter";
	case RPMB_PT_REQ_AUTH_WRITE: return "auth-write";
	case RPMB_PT_REQ_AUTH_READ: return "auth-read";
	case RPMB_PT_REQ_RESULT_READ: return "result-read";
	default: return "type";
	}
}

static uint32_t header_reply(unsigned char *sb, uint32_t status,
			     uint32_t moved)
{
	hdr_set(sb, 4, status);
	hdr_set(sb, 8, moved);
	hdr_set(sb, 0xc, 20);
	return 20;
}

/* ---- the log file ---- */

void rpmb_pt_log(struct rpmb_pt *p, const char *line)
{
	char buf[1200];
	struct timespec ts;
	struct tm tm;
	size_t n;

	if (p->log_fd < 0)
		return;
	clock_gettime(CLOCK_REALTIME, &ts);
	gmtime_r(&ts.tv_sec, &tm);
	n = strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
	n += (size_t)snprintf(buf + n, sizeof(buf) - n, ".%03ldZ %s\n",
			      ts.tv_nsec / 1000000, line);
	if (n >= sizeof(buf))
		n = sizeof(buf) - 1;
	/* one write per line: an append is atomic for a regular file */
	if (write(p->log_fd, buf, n) < 0)
		return;
}

/* ---- the SG_IO transport ---- */

#ifdef __linux__
/* One SCSI command through sg_io_v4 on the node: dir_in 1 reads len bytes
 * into buf, 0 writes len bytes from buf. 0, or a negative status. */
static int sg_cmd(struct rpmb_pt *p, const uint8_t *cdb, size_t cdblen,
		  int dir_in, void *buf, size_t len, const char *what,
		  char *err, size_t errlen)
{
	struct sg_io_v4 io;
	uint8_t sense[96];

	memset(&io, 0, sizeof(io));
	memset(sense, 0, sizeof(sense));
	io.guard = 'Q';
	io.protocol = BSG_PROTOCOL_SCSI;
	io.subprotocol = BSG_SUB_PROTOCOL_SCSI_CMD;
	io.request_len = (uint32_t)cdblen;
	io.request = (uintptr_t)cdb;
	io.max_response_len = sizeof(sense);
	io.response = (uintptr_t)sense;
	if (dir_in) {
		io.din_xfer_len = (uint32_t)len;
		io.din_xferp = (uintptr_t)buf;
	} else {
		io.dout_xfer_len = (uint32_t)len;
		io.dout_xferp = (uintptr_t)buf;
	}
	io.timeout = 30000;	/* ms; the vendor leaves the kernel's 60 s */
	if (ioctl(p->dev_fd, SG_IO, &io)) {
		int e = errno;

		snprintf(err, errlen, "%s: SG_IO failed: errno %d", what, e);
		return e > 0 ? -e : -EIO;
	}
	if (io.device_status || io.transport_status || io.driver_status) {
		snprintf(err, errlen, "%s: device status 0x%x, transport "
			 "status 0x%x, driver status 0x%x, sense key 0x%x",
			 what, io.device_status, io.transport_status,
			 io.driver_status,
			 io.response_len >= 3 ? sense[2] & 0xf : 0);
		return -5;
	}
	if (dir_in && io.din_resid) {
		snprintf(err, errlen, "%s: short by %u bytes", what,
			 io.din_resid);
		return -5;
	}
	return 0;
}

int rpmb_pt_sg_xfer(void *ctx, int dir_in, void *buf, size_t len, char *err,
		    size_t errlen)
{
	struct rpmb_pt *p = ctx;
	uint8_t cdb[12] = { 0 };

	/* UFS RPMB: SECURITY PROTOCOL IN/OUT, protocol 0xec, specific 0x0001,
	 * INC_512 clear, the length in bytes (bytes 6..9, big-endian) */
	cdb[0] = dir_in ? 0xa2 : 0xb5;
	cdb[1] = 0xec;
	cdb[2] = 0x00;
	cdb[3] = 0x01;
	cdb[6] = (uint8_t)(len >> 24);
	cdb[7] = (uint8_t)(len >> 16);
	cdb[8] = (uint8_t)(len >> 8);
	cdb[9] = (uint8_t)len;
	return sg_cmd(p, cdb, sizeof(cdb), dir_in, buf, len,
		      dir_in ? "spi" : "spo", err, errlen);
}

/* REQUEST SENSE once after the open, as the vendor's init does: the
 * W-LU answers its first command after a reset or a runtime resume with
 * a unit attention, which this reads away. Not an RPMB frame: 18 bytes
 * of sense data come back, nothing goes to the device. Returns 0 and
 * the sense key in info, or the transport's error (the init goes on). */
int rpmb_pt_request_sense(struct rpmb_pt *p, char *info, size_t infolen)
{
	const uint8_t cdb[6] = { 0x03, 0, 0, 0, 18, 0 };
	uint8_t sense[18];
	int ret;

	memset(sense, 0, sizeof(sense));
	ret = sg_cmd(p, cdb, sizeof(cdb), 1, sense, sizeof(sense),
		     "request-sense", info, infolen);
	if (ret == 0)
		snprintf(info, infolen, "request-sense ok, sense key 0x%x",
			 sense[2] & 0xf);
	return ret;
}
#else
int rpmb_pt_sg_xfer(void *ctx, int dir_in, void *buf, size_t len, char *err,
		    size_t errlen)
{
	(void)ctx; (void)dir_in; (void)buf; (void)len;
	snprintf(err, errlen, "no SG_IO on this platform");
	return -ENOSYS;
}

int rpmb_pt_request_sense(struct rpmb_pt *p, char *info, size_t infolen)
{
	(void)p;
	snprintf(info, infolen, "no SG_IO on this platform");
	return -ENOSYS;
}
#endif

/* ---- open/close ---- */

int rpmb_pt_open(struct rpmb_pt *p, const char *dev, const char *log,
		 int writes, uint32_t fpt, uint32_t sectors, char *err,
		 size_t errlen)
{
	struct stat st;

	memset(p, 0, sizeof(*p));
	p->dev_fd = -1;
	p->log_fd = -1;
	if (!dev || !*dev) {
		snprintf(err, errlen, "no RPMB device path");
		return -1;
	}
	if (fpt == 0 || fpt > RPMB_PT_MAX_FRAMES * 16) {
		snprintf(err, errlen, "frames per transfer %u: not plausible",
			 fpt);
		return -1;
	}
	p->dev_fd = open(dev, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
	if (p->dev_fd < 0) {
		snprintf(err, errlen, "open %s: errno %d", dev, errno);
		return -1;
	}
	if (fstat(p->dev_fd, &st) || !S_ISCHR(st.st_mode)) {
		snprintf(err, errlen, "%s is not a character device", dev);
		rpmb_pt_close(p);
		return -1;
	}
	if (log && *log) {
		p->log_fd = open(log, O_WRONLY | O_APPEND | O_CREAT |
				 O_NOFOLLOW | O_CLOEXEC, 0600);
		if (p->log_fd < 0) {
			snprintf(err, errlen, "open log %s: errno %d", log,
				 errno);
			rpmb_pt_close(p);
			return -1;
		}
		if (fstat(p->log_fd, &st) || !S_ISREG(st.st_mode)) {
			snprintf(err, errlen, "%s is not a regular file", log);
			rpmb_pt_close(p);
			return -1;
		}
	}
	p->writes = writes ? 1 : 0;
	p->fpt = fpt;
	p->sectors = sectors;
	p->xfer = rpmb_pt_sg_xfer;
	p->xfer_ctx = p;
	return 0;
}

void rpmb_pt_close(struct rpmb_pt *p)
{
	if (p->dev_fd >= 0)
		close(p->dev_fd);
	if (p->log_fd >= 0)
		close(p->log_fd);
	p->dev_fd = -1;
	p->log_fd = -1;
}

/* ---- the request frames: where they are, what they ask ---- */

/* The frames' offset from the header word at +0xc (0x18 observed; 0 is
 * taken as that), bounded to the buffer. 0 when it does not fit. */
static uint32_t req_offset(const unsigned char *sb, uint32_t sb_len,
			   uint32_t frames)
{
	uint32_t off = hdr_get(sb, 0xc);

	if (off == 0)
		off = RPMB_PT_REQ_DEFAULT;
	if (off < RPMB_PT_HDR || off > sb_len ||
	    frames > (sb_len - off) / RPMB_PT_FRAME)
		return 0;
	return off;
}

/* A PROGRAM KEY request among the frames: refused whoever asks. */
static int has_program_key(const uint8_t *frames, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (be16(frames + i * RPMB_PT_FRAME + F_TYPE) ==
		    RPMB_PT_REQ_PROGRAM_KEY)
			return 1;
	return 0;
}

static void describe_reply(struct desc *d, const uint8_t *f, int counter)
{
	add(d, " resp 0x%04x addr 0x%04x", be16(f + F_TYPE), be16(f + F_ADDR));
	if (!counter)
		add(d, " count %u", be16(f + F_COUNT));
	add(d, " counter %u -> result 0x%04x", be32(f + F_COUNTER),
	    be16(f + F_RESULT));
}

/* ---- 0x102 read ---- */

static uint32_t serve_read(struct rpmb_pt *p, unsigned char *sb,
			   uint32_t sb_len, uint32_t n, struct desc *d)
{
	static uint8_t req[RPMB_PT_MAX_FRAMES][RPMB_PT_FRAME];
	uint32_t ntx, t, off;
	char err[160];
	int ret;

	ntx = (n + p->fpt - 1) / p->fpt;
	if (n == 0 || n > (sb_len - RPMB_PT_HDR) / RPMB_PT_FRAME ||
	    ntx > RPMB_PT_MAX_FRAMES ||
	    (off = req_offset(sb, sb_len, ntx)) == 0) {
		add(d, "REFUSED frame count does not fit the buffer -> status -1");
		p->refused++;
		return header_reply(sb, STATUS_REFUSED, 0);
	}
	/* The replies overwrite the request frames: copy them first. */
	for (t = 0; t < ntx; t++)
		memcpy(req[t], sb + off + t * RPMB_PT_FRAME, RPMB_PT_FRAME);
	if (has_program_key(req[0], ntx)) {
		add(d, "REFUSED program-key request type 0x%04x -> status -1",
		    RPMB_PT_REQ_PROGRAM_KEY);
		p->refused++;
		return header_reply(sb, STATUS_REFUSED, 0);
	}
	for (t = 0; t < ntx; t++) {
		uint32_t k = n - t * p->fpt;
		uint8_t *out = sb + RPMB_PT_HDR + t * p->fpt * RPMB_PT_FRAME;
		uint32_t type = be16(req[t] + F_TYPE);

		if (k > p->fpt)
			k = p->fpt;
		add(d, "%stx%u %s", t ? "; " : "", t + 1, type_name(type));
		if (type != RPMB_PT_REQ_READ_CTR &&
		    type != RPMB_PT_REQ_AUTH_READ)
			add(d, " 0x%04x", type);
		add(d, " addr 0x%04x k %u ", be16(req[t] + F_ADDR), k);
		add_nonce(d, req[t]);
		ret = p->xfer(p->xfer_ctx, 0, req[t], RPMB_PT_FRAME, err,
			      sizeof(err));
		if (ret) {
			add(d, " spo FAILED (%s) -> status %d", err, ret);
			return header_reply(sb, (uint32_t)ret, 0);
		}
		add(d, " spo %u ok,", RPMB_PT_FRAME);
		ret = p->xfer(p->xfer_ctx, 1, out, (size_t)k * RPMB_PT_FRAME,
			      err, sizeof(err));
		if (ret) {
			add(d, " spi FAILED (%s) -> status %d", err, ret);
			return header_reply(sb, (uint32_t)ret, 0);
		}
		add(d, " spi %u ok,", k * RPMB_PT_FRAME);
		/* the last frame carries the result (and the MAC, not logged) */
		describe_reply(d, out + (k - 1) * RPMB_PT_FRAME, 0);
	}
	return header_reply(sb, 0, n * RPMB_PT_FRAME);
}

/* ---- 0x103 write ---- */

static uint32_t serve_write(struct rpmb_pt *p, unsigned char *sb,
			    uint32_t sb_len, uint32_t n, struct desc *d)
{
	/* the vendor's constant RESULT READ request frame: all zero but the
	 * request type 0x0005 */
	static const uint8_t result_read[RPMB_PT_FRAME] = {
		[F_TYPE + 1] = RPMB_PT_REQ_RESULT_READ };
	uint8_t rr[RPMB_PT_FRAME];
	uint8_t res[RPMB_PT_FRAME];
	uint32_t w4 = hdr_get(sb, 0x14), t, off;
	char err[160];
	int ret;

	if (w4 == 0 || w4 > p->fpt || n == 0 || n % w4 ||
	    n > RPMB_PT_MAX_FRAMES * 16 ||
	    (off = req_offset(sb, sb_len, n)) == 0) {
		add(d, "REFUSED bad frame counts (w4 %u) -> status -1", w4);
		p->refused++;
		return header_reply(sb, STATUS_REFUSED, 0);
	}
	if (has_program_key(sb + off, n)) {
		add(d, "REFUSED program-key request type 0x%04x -> status -1",
		    RPMB_PT_REQ_PROGRAM_KEY);
		p->refused++;
		return header_reply(sb, STATUS_REFUSED, 0);
	}
	if (!p->writes) {
		const uint8_t *f = sb + off;

		add(d, "REFUSED writes disabled (type 0x%04x addr 0x%04x k %u "
		    "counter %u) -> status -1", be16(f + F_TYPE),
		    be16(f + F_ADDR), n, be32(f + F_COUNTER));
		p->refused++;
		return header_reply(sb, STATUS_REFUSED, 0);
	}
	for (t = 0; t < n / w4; t++) {
		uint8_t *frames = sb + off + t * w4 * RPMB_PT_FRAME;
		uint32_t type = be16(frames + F_TYPE);

		add(d, "%stx%u %s", t ? "; " : "", t + 1, type_name(type));
		if (type != RPMB_PT_REQ_AUTH_WRITE)
			add(d, " 0x%04x", type);
		add(d, " addr 0x%04x k %u counter %u", be16(frames + F_ADDR),
		    w4, be32(frames + F_COUNTER));
		ret = p->xfer(p->xfer_ctx, 0, frames,
			      (size_t)w4 * RPMB_PT_FRAME, err, sizeof(err));
		if (ret) {
			add(d, " spo FAILED (%s) -> status %d", err, ret);
			return header_reply(sb, (uint32_t)ret, 0);
		}
		add(d, " spo %u ok,", w4 * RPMB_PT_FRAME);
		memcpy(rr, result_read, sizeof(rr));
		ret = p->xfer(p->xfer_ctx, 0, rr, RPMB_PT_FRAME, err,
			      sizeof(err));
		if (ret) {
			add(d, " spo result-read FAILED (%s) -> status %d",
			    err, ret);
			return header_reply(sb, (uint32_t)ret, 0);
		}
		add(d, " spo result-read ok,");
		memset(res, 0, sizeof(res));
		ret = p->xfer(p->xfer_ctx, 1, res, RPMB_PT_FRAME, err,
			      sizeof(err));
		if (ret) {
			add(d, " spi FAILED (%s) -> status %d", err, ret);
			return header_reply(sb, (uint32_t)ret, 0);
		}
		add(d, " spi %u ok,", RPMB_PT_FRAME);
		/* transfer t+1's frames start past the result frame, so
		 * writing each result at +0x14 clobbers no frame still to
		 * be sent */
		memcpy(sb + RPMB_PT_HDR, res, sizeof(res));
		describe_reply(d, res, 1);
	}
	return header_reply(sb, 0, RPMB_PT_FRAME);
}

/* ---- 0x101, 0x104, unknown ---- */

static uint32_t put_words(unsigned char *sb, const uint32_t *w, size_t n)
{
	memcpy(sb, w, n * sizeof(*w));
	return (uint32_t)(n * sizeof(*w));
}

static uint32_t serve_init(struct rpmb_pt *p, unsigned char *sb, uint32_t sub,
			   struct desc *d)
{
	const uint32_t one[5] = { 0x101, 1, 0, p->sectors, p->fpt };
	const uint32_t zero[5] = { 0x101, 1, 0xffffffffu, 0, 0 };
	const uint32_t other[10] = { 0x101, 2, 0, p->sectors, p->fpt,
				     RPMB_PT_TYPE_UFS };

	if (sub == 0) {
		add(d, "init sub 0 -> constant {1, -1, 0, 0}");
		return put_words(sb, zero, 5);
	}
	add(d, "init sub %u -> size %u fpt %u type %u", sub, p->sectors,
	    p->fpt, RPMB_PT_TYPE_UFS);
	return sub == 1 ? put_words(sb, one, 5) : put_words(sb, other, 10);
}

uint32_t rpmb_pt_serve(struct rpmb_pt *p, unsigned char *sb, uint32_t sb_len,
		       char *desc, size_t desclen)
{
	struct desc d = { desc, desclen, 0 };
	uint32_t cmd = hdr_get(sb, 0), n = hdr_get(sb, 4), len;
	uint32_t per_tx = cmd == 0x102 ? p->fpt
			: cmd == 0x103 ? hdr_get(sb, 0x14) : 0;

	if (desclen)
		desc[0] = 0;
	p->requests++;
	add(&d, "request %lu: command 0x%x, frames %u (%u per tx): ",
	    p->requests, cmd, n, per_tx);
	switch (cmd) {
	case 0x101:
		len = serve_init(p, sb, n, &d);
		break;
	case 0x102:
		len = serve_read(p, sb, sb_len, n, &d);
		break;
	case 0x103:
		len = serve_write(p, sb, sb_len, n, &d);
		break;
	case 0x104: {
		const uint32_t none[4] = { 0x104, 0xffffffffu, 0, 16 };

		add(&d, "partition config -> not found");
		len = put_words(sb, none, 4);
		break;
	}
	default: {
		const uint32_t unk[5] = { cmd, STATUS_UNKNOWN, 0, 20 };

		add(&d, "unknown command -> status 0x%x", STATUS_UNKNOWN);
		len = put_words(sb, unk, 5);
		break;
	}
	}
	if (desc)
		rpmb_pt_log(p, desc);
	return len;
}
