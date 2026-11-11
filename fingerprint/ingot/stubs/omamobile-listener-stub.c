// SPDX-License-Identifier: MIT
/*
 * omamobile-listener-stub: our librpmb.so and libssd.so for the Solana Saga's
 * fingerprint chroot (stage S3). Built twice from this file, with
 * -DSTUB_RPMB and with -DSTUB_SSD (fingerprint/ingot/Makefile).
 *
 * Qualcomm's listener daemon, qseecomd, serves TrustZone's requests for
 * storage. Its RPMB and SSD libraries reach the UFS RPMB partition and the
 * ssd partition; nothing of ours may touch the real RPMB or a block device.
 *
 * librpmb.so (-DSTUB_RPMB) is a FILE-BACKED RPMB EMULATOR at the listener
 * boundary (omamobile-rpmb-emu.c, #included here so the library stays one
 * link unit). It answers TrustZone as a 4 MiB UFS RPMB would (8192
 * sectors, 64 frames per transfer, type 9): program key, read counter,
 * authenticated read and write, with real HMAC-SHA256 MACs once TrustZone
 * has programmed its key, and result 0x0007 (key not yet programmed)
 * before that. Its state lives in a directory inside the chroot, taken
 * from OMAMOBILE_RPMB_EMU_DIR (default /data/vendor/omamobile-rpmb-emu; the
 * stage tool creates it root:root 0700):
 *   rpmb.img  the data area, 16384 blocks of 256 bytes, zero-filled
 *             (ftruncate) on first use;
 *   state     magic, version, key_programmed, the 32-byte key, the write
 *             counter; created on first use.
 * Both are opened in rpmb_init_service(), as root, before qseecomd drops to
 * uid 1000, and kept for the listener thread; a missing directory or a
 * failed open fails the init, so qseecomd exits loudly. SAFETY: the
 * emulator opens exactly these two regular files under its state directory
 * (O_NOFOLLOW, checked S_ISREG) and no device; besides them the only thing
 * opened is /dev/qseecom, by libQSEEComAPI.so when the listener registers.
 * It never logs the key or the data, only the first 4 bytes of a nonce.
 *
 * libssd.so (-DSTUB_SSD) is still a stub: it answers every request as a
 * failed operation and logs it. It opens no device and no file.
 *
 * What qseecomd expects (its disassembly):
 *  - it dlopen()s the library by name (RTLD_NOW), so this one must come
 *    first in LD_LIBRARY_PATH;
 *  - int <svc>_init_service(void): called once, as root, before qseecomd
 *    drops to uid/gid 1000. Nonzero makes qseecomd log RPMB_INIT/SSD_INIT
 *    failed and exit;
 *  - int <svc>_start(uint32_t listener_id): called later with the table's
 *    id (0x2000 RPMB, 0x3000 SSD). It must register the listener, start its
 *    own thread and return: qseecomd calls every service's start in turn,
 *    sets vendor.sys.listeners.registered and pause()s. 0 is success; the
 *    result is only logged;
 *  - <svc>_close: in the table but never called.
 *
 * Wire formats (the vendor libraries' disassembly):
 *  RPMB, buffer 0x6400, served in place in the shared buffer: request
 *    command at +0 (0x101 init, 0x102 read, 0x103 write, 0x104 cfg), +4 the
 *    frame count (0x101: sub-op), +0x14 frames per transfer (0x103), the
 *    request frames at +0x18. Reply: +4 status, +8 bytes moved, +0xc 20,
 *    the reply frames written at +0x14; 20 bytes are sent (0x101 and 0x104
 *    have their own short shapes, see omamobile-rpmb-emu.c).
 *  SSD, buffer 0x5000, request copied out (0x2008 bytes): command at +0
 *    (0x202 read, 0x203 write), data at +8. Reply: +0 command, +4 status,
 *    +8 byte count, +0xc data. Read: status 0 success, 3 failed, sent as
 *    0x200c bytes; write: 0 success, 2 failed, sent as 12 bytes. An unknown
 *    command gets all zeroes but status 0xffffffff, 12 bytes.
 *
 * Logs go to stderr and to Android's log (__android_log_print), so they
 * show however the runner captures the daemon.
 *
 * Build with the Android NDK (bionic, aarch64), see fingerprint/ingot/Makefile.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define EXPORT __attribute__((visibility("default")))

/* libQSEEComAPI.so */
struct QSEECom_handle {
	unsigned char *ion_sbuffer;
};

int QSEECom_register_listener(struct QSEECom_handle **handle,
			      uint32_t lstnr_id, uint32_t sb_length,
			      uint32_t flags);
int QSEECom_receive_req(struct QSEECom_handle *handle, void *buf,
			uint32_t len);
int QSEECom_send_resp(struct QSEECom_handle *handle, void *send_buf,
		      uint32_t len);
int QSEECom_unregister_listener(struct QSEECom_handle *handle);

/* liblog.so */
int __android_log_print(int prio, const char *tag, const char *fmt, ...);
#define LOG_INFO	4
#define LOG_WARN	5
#define LOG_ERROR	6

/* receive_req is interrupted by a signal: ask again (as the vendor's do) */
#define RECEIVE_RESTART	(-512)

#if defined(STUB_RPMB)
#define SVC		"rpmb"
#define TAG		"omamobile-rpmb-emu"
#define SB_LENGTH	0x6400u
#define SERVES		"served by the file-backed emulator"
#elif defined(STUB_SSD)
#define SVC		"ssd"
#define TAG		"omamobile-ssd-stub"
#define SB_LENGTH	0x5000u
#define SERVES		"every request fails"
#else
#error "build with -DSTUB_RPMB or -DSTUB_SSD"
#endif

static struct QSEECom_handle *handle;
static pthread_t thread;
static uint32_t listener;
static unsigned long requests;

__attribute__((format(printf, 2, 3)))
static void say(int prio, const char *fmt, ...)
{
	char buf[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	dprintf(STDERR_FILENO, "%s[%d]: %s\n", TAG, gettid(), buf);
	__android_log_print(prio, TAG, "%s", buf);
}

#if defined(STUB_RPMB)

#include <stdlib.h>
#include "omamobile-rpmb-emu.c"

#define EMU_DIR_DEFAULT	"/data/vendor/omamobile-rpmb-emu"

static struct rpmb_emu emu;

/* Requests are served one at a time by the listener thread, so the
 * emulator's state needs no lock. */
static uint32_t serve_one(unsigned char *sb)
{
	char desc[768];
	uint32_t len;

	len = rpmb_emu_serve(&emu, sb, SB_LENGTH, desc, sizeof(desc));
	requests++;
	say(LOG_INFO, "listener 0x%x request %lu: %s", listener, requests,
	    desc);
	return len;
}

static int init_service(void)
{
	const char *dir = getenv("OMAMOBILE_RPMB_EMU_DIR"), *probe;
	char err[256];

	if (!dir || !*dir)
		dir = EMU_DIR_DEFAULT;
	if (rpmb_emu_open(&emu, dir, err, sizeof(err))) {
		say(LOG_ERROR, "rpmb_init_service: emulator: %s", err);
		return -1;
	}
	probe = getenv("OMAMOBILE_RPMB_EMU_PROBE");
	if (probe && !strcmp(probe, "unauthenticated-ok"))
		emu.probe_unauth_ok = 1;
	say(LOG_INFO, "rpmb emulator: state %s, key programmed %u, "
	    "counter %u%s", dir, emu.st.key_programmed, emu.st.write_counter,
	    emu.probe_unauth_ok ? ", PROBE: unauthenticated OK reads" : "");
	return 0;
}

static void *serve(void *arg)
{
	int ret;

	(void)arg;
	for (;;) {
		unsigned char *sb = handle->ion_sbuffer;

		ret = QSEECom_receive_req(handle, sb, SB_LENGTH);
		if (ret == RECEIVE_RESTART)
			continue;
		if (ret) {
			say(LOG_ERROR, "receive_req failed: %d (errno %d), "
			    "listener thread ends", ret, errno);
			return NULL;
		}
		ret = QSEECom_send_resp(handle, sb, serve_one(sb));
		if (ret)
			say(LOG_ERROR, "send_resp failed: %d (errno %d)",
			    ret, errno);
	}
}

#else /* STUB_SSD */

/* The first 32 bytes of a request, as hex words. */
static void log_request(const void *req, uint32_t cmd)
{
	const uint32_t *w = req;
	char hex[8 * 9 + 1];
	size_t i, n = 0;

	for (i = 0; i < 8; i++)
		n += (size_t)snprintf(hex + n, sizeof(hex) - n, " %08x", w[i]);
	requests++;
	say(LOG_INFO, "listener 0x%x request %lu: command 0x%x, failing it;%s",
	    listener, requests, cmd, hex);
}

#define SSD_REQ_LEN		0x2008u
#define SSD_DATA_LEN		0x2000u
#define SSD_CMD_READ		0x202u
#define SSD_CMD_WRITE		0x203u
#define SSD_STATUS_WRITE_FAILED	2u
#define SSD_STATUS_READ_FAILED	3u
#define SSD_STATUS_UNKNOWN	0xffffffffu

struct ssd_resp {
	uint32_t cmd;
	uint32_t status;
	uint32_t count;
	unsigned char data[SSD_DATA_LEN];
} __attribute__((packed));

_Static_assert(sizeof(struct ssd_resp) == 0x200c, "ssd reply layout");

static uint32_t serve_one(const unsigned char *req, struct ssd_resp *resp)
{
	uint32_t cmd;

	memcpy(&cmd, req, sizeof(cmd));
	log_request(req, cmd);
	memset(resp, 0, sizeof(*resp));
	switch (cmd) {
	case SSD_CMD_READ:
		resp->cmd = cmd;
		resp->status = SSD_STATUS_READ_FAILED;
		return sizeof(*resp);
	case SSD_CMD_WRITE:
		resp->cmd = cmd;
		resp->status = SSD_STATUS_WRITE_FAILED;
		return 12;
	default:
		resp->status = SSD_STATUS_UNKNOWN;
		return 12;
	}
}

static void *serve(void *arg)
{
	static unsigned char req[SSD_REQ_LEN];
	static struct ssd_resp resp;
	int ret;

	(void)arg;
	for (;;) {
		memset(req, 0, sizeof(req));
		ret = QSEECom_receive_req(handle, req, sizeof(req));
		if (ret == RECEIVE_RESTART)
			continue;
		if (ret) {
			say(LOG_ERROR, "receive_req failed: %d (errno %d), "
			    "listener thread ends", ret, errno);
			return NULL;
		}
		ret = QSEECom_send_resp(handle, &resp, serve_one(req, &resp));
		if (ret)
			say(LOG_ERROR, "send_resp failed: %d (errno %d)",
			    ret, errno);
	}
}

static int init_service(void)
{
	say(LOG_INFO, "%s_init_service: stub, nothing opened", SVC);
	return 0;
}

#endif

static int start(uint32_t lstnr_id)
{
	int ret;

	if (handle) {
		say(LOG_WARN, "%s_start(0x%x): already serving 0x%x", SVC,
		    lstnr_id, listener);
		return 0;
	}
	listener = lstnr_id;
	ret = QSEECom_register_listener(&handle, lstnr_id, SB_LENGTH, 0);
	if (ret) {
		say(LOG_ERROR, "%s_start: register_listener(0x%x, 0x%x) "
		    "failed: %d (errno %d)", SVC, lstnr_id, SB_LENGTH, ret,
		    errno);
		handle = NULL;
		return -1;
	}
	ret = pthread_create(&thread, NULL, serve, NULL);
	if (ret) {
		say(LOG_ERROR, "%s_start: pthread_create failed: %d", SVC, ret);
		QSEECom_unregister_listener(handle);
		handle = NULL;
		return -1;
	}
	say(LOG_INFO, "%s_start: listener 0x%x registered (buffer 0x%x), "
	    SERVES, SVC, lstnr_id, SB_LENGTH);
	return 0;
}

static int close_service(void)
{
	int ret;

	if (!handle)
		return 0;
	ret = QSEECom_unregister_listener(handle);
	if (ret) {
		say(LOG_ERROR, "%s_close: unregister_listener failed: %d", SVC,
		    ret);
		return -1;
	}
	pthread_join(thread, NULL);
	handle = NULL;
	say(LOG_INFO, "%s_close: listener 0x%x unregistered after %lu "
	    "requests", SVC, listener, requests);
	return 0;
}

#if defined(STUB_RPMB)
EXPORT int rpmb_init_service(void) { return init_service(); }
EXPORT int rpmb_start(uint32_t lstnr_id) { return start(lstnr_id); }
EXPORT int rpmb_close(void) { return close_service(); }
#else
EXPORT int ssd_init_service(void) { return init_service(); }
EXPORT int ssd_start(uint32_t lstnr_id) { return start(lstnr_id); }
EXPORT int ssd_close(void) { return close_service(); }
#endif
