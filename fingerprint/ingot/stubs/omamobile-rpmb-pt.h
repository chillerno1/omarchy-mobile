// SPDX-License-Identifier: MIT
/*
 * omamobile-rpmb-pt: the RPMB pass-through at the QSEE listener boundary
 * (listener 0x2000). TrustZone's frames go to the UFS RPMB well-known LU
 * unmodified, the chip's replies come back unmodified; the listener never
 * builds, changes or replays a frame. Pure code apart from the one SG_IO
 * transport (rpmb_pt_sg_xfer), so the host test (test/rpmb-pt-test.c)
 * drives the same handlers the phone runs with a fake transport. See
 * omamobile-listener-stub.c for the wire format and the safety claim.
 */
#ifndef OMAMOBILE_RPMB_PT_H
#define OMAMOBILE_RPMB_PT_H

#include <stddef.h>
#include <stdint.h>

#define RPMB_PT_FRAME		512u
#define RPMB_PT_HDR		0x14u		/* reply frames start here */
#define RPMB_PT_REQ_DEFAULT	0x18u		/* request frames, if +0xc is 0 */
#define RPMB_PT_MAX_FRAMES	64u		/* > (0x6400 - 0x14) / 512 */
#define RPMB_PT_TYPE_UFS	9u

/* JEDEC RPMB request types (frame bytes 510..511, big-endian) */
#define RPMB_PT_REQ_PROGRAM_KEY	0x0001u
#define RPMB_PT_REQ_READ_CTR	0x0002u
#define RPMB_PT_REQ_AUTH_WRITE	0x0003u
#define RPMB_PT_REQ_AUTH_READ	0x0004u
#define RPMB_PT_REQ_RESULT_READ	0x0005u

/*
 * One SECURITY PROTOCOL transfer: dir_in 0 = SECURITY PROTOCOL OUT of len
 * bytes from buf, 1 = SECURITY PROTOCOL IN of len bytes into buf. Returns 0,
 * or a negative status for the listener header (-errno, or -5 for a SCSI
 * level error) with a reason in err.
 */
typedef int (*rpmb_pt_xfer_fn)(void *ctx, int dir_in, void *buf, size_t len,
			       char *err, size_t errlen);

struct rpmb_pt {
	int dev_fd;		/* the RPMB W-LU's bsg node, or -1 */
	int log_fd;		/* the root-only audit log, or -1 */
	int writes;		/* 0: every 0x103 is refused untouched */
	uint32_t fpt;		/* frames per transfer (bRPMB_ReadWriteSize) */
	uint32_t sectors;	/* the RPMB's size in 512-byte sectors */
	rpmb_pt_xfer_fn xfer;	/* the transport (SG_IO, or the test's fake) */
	void *xfer_ctx;
	unsigned long requests;
	unsigned long refused;
};

/*
 * Open the node (O_RDWR|O_NOFOLLOW|O_CLOEXEC, must be a character device)
 * and the log (append, created 0600), set the parameters and the SG_IO
 * transport. 0 on success; -1 with a reason in err. Nothing else is ever
 * opened.
 */
int rpmb_pt_open(struct rpmb_pt *p, const char *dev, const char *log,
		 int writes, uint32_t fpt, uint32_t sectors, char *err,
		 size_t errlen);
void rpmb_pt_close(struct rpmb_pt *p);

/* The real transport: SG_IO (sg_io_v4) on p->dev_fd; ctx is the struct. */
int rpmb_pt_sg_xfer(void *ctx, int dir_in, void *buf, size_t len, char *err,
		    size_t errlen);

/*
 * Serve one request in place in sb (sb_len bytes). Returns the number of
 * bytes to send back; desc gets a one-line decode for the log (header
 * fields only: never a key, a MAC or a data block). The same line, with a
 * timestamp, is appended to the log file.
 */
uint32_t rpmb_pt_serve(struct rpmb_pt *p, unsigned char *sb, uint32_t sb_len,
		       char *desc, size_t desclen);

/* Append one timestamped line to the log file (no-op without one). */
void rpmb_pt_log(struct rpmb_pt *p, const char *line);

#endif
