// SPDX-License-Identifier: MIT
/*
 * omamobile-rpmb-emu: a file-backed RPMB at the QSEE listener boundary
 * (listener 0x2000). Pure code: no QSEECom, no logging, plain fds, so the
 * host test (test/rpmb-emu-test.c) drives the same handlers the phone runs.
 * See omamobile-listener-stub.c for the wire format and the safety claim.
 */
#ifndef OMAMOBILE_RPMB_EMU_H
#define OMAMOBILE_RPMB_EMU_H

#include <stddef.h>
#include <stdint.h>

#define RPMB_EMU_BLOCKS		16384u		/* 256-byte half sectors */
#define RPMB_EMU_BLOCK		256u
#define RPMB_EMU_SECTORS	8192u		/* 512-byte sectors, 4 MiB */
#define RPMB_EMU_FPT		64u		/* frames per transfer */
#define RPMB_EMU_TYPE		9u		/* UFS */
#define RPMB_EMU_FRAME		512u
#define RPMB_EMU_HDR		0x14u		/* reply frames start here */
#define RPMB_EMU_REQ		0x18u		/* request frames start here */
#define RPMB_EMU_KEY		32u

#define RPMB_EMU_STATE_MAGIC	0x4550524fu	/* "ORPE" */
#define RPMB_EMU_STATE_VERSION	1u

/* The `state` file, as written (host byte order). */
struct rpmb_emu_state {
	uint32_t magic;
	uint32_t version;
	uint32_t key_programmed;
	uint8_t key[RPMB_EMU_KEY];
	uint32_t write_counter;
};

struct rpmb_emu {
	int img_fd;
	int state_fd;
	struct rpmb_emu_state st;
	/* A test knob (OMAMOBILE_RPMB_EMU_PROBE=unauthenticated-ok): before
	 * a key is programmed, answer an authenticated read with result
	 * 0x0000, zero data and no MAC instead of 0x0007. It shows whether
	 * TrustZone checks the MAC (it must refuse this) or only the result.
	 * Never set by the stage tool on its own. */
	int probe_unauth_ok;
};

/*
 * Open (and on first use create) <dir>/rpmb.img and <dir>/state, the only
 * two files the emulator ever opens. 0 on success; -1 with a reason in err.
 */
int rpmb_emu_open(struct rpmb_emu *e, const char *dir, char *err,
		  size_t errlen);
void rpmb_emu_close(struct rpmb_emu *e);

/*
 * Serve one request in place in sb (sb_len bytes). Returns the number of
 * bytes to send back; desc gets a one-line decode for the log (never the
 * key, never the data).
 */
uint32_t rpmb_emu_serve(struct rpmb_emu *e, unsigned char *sb,
			uint32_t sb_len, char *desc, size_t desclen);

/* HMAC-SHA256, exposed for the test's known-answer vectors. */
#define RPMB_EMU_SHA256_LEN	32u
void rpmb_emu_hmac_sha256(const uint8_t *key, size_t keylen,
			  const uint8_t *msg, size_t len,
			  uint8_t out[RPMB_EMU_SHA256_LEN]);

#endif
