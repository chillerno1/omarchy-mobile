// SPDX-License-Identifier: MIT
/*
 * omamobile-listener-stub: our librpmb.so and libssd.so for the Solana Saga's
 * fingerprint chroot (stage S3). Built twice from this file, with
 * -DSTUB_RPMB and with -DSTUB_SSD (fingerprint/ingot/Makefile).
 *
 * Qualcomm's listener daemon, qseecomd, serves TrustZone's requests for
 * storage. Its RPMB and SSD libraries reach the UFS RPMB partition and the
 * ssd partition; in S3 nothing may touch RPMB or a block device, so these
 * stand-ins answer every request as a failed operation and log it. They
 * open no device and no file: the only thing opened is /dev/qseecom, by
 * libQSEEComAPI.so when the listener registers.
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
 *    command at +0 (0x101 init, 0x102 read, 0x103 write, 0x104 cfg). Reply
 *    20 bytes: +0 command (left as is), +4 status (0 success, 0xffffffff
 *    failed operation, 0xfffffff9 unknown command), +8 0, +0xc 0x14.
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
#define TAG		"omamobile-rpmb-stub"
#define SB_LENGTH	0x6400u
#elif defined(STUB_SSD)
#define SVC		"ssd"
#define TAG		"omamobile-ssd-stub"
#define SB_LENGTH	0x5000u
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
	char buf[512];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	dprintf(STDERR_FILENO, "%s[%d]: %s\n", TAG, gettid(), buf);
	__android_log_print(prio, TAG, "%s", buf);
}

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

#if defined(STUB_RPMB)

#define RPMB_STATUS_FAILED	0xffffffffu
#define RPMB_STATUS_UNKNOWN	0xfffffff9u
#define RPMB_RESP_LEN		20u

static uint32_t serve_one(unsigned char *sb)
{
	uint32_t *w = (uint32_t *)sb;
	uint32_t cmd = w[0];

	log_request(sb, cmd);
	w[1] = cmd >= 0x101 && cmd <= 0x104 ? RPMB_STATUS_FAILED
					    : RPMB_STATUS_UNKNOWN;
	w[2] = 0;
	w[3] = RPMB_RESP_LEN;
	return RPMB_RESP_LEN;
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

#endif

static int init_service(void)
{
	say(LOG_INFO, "%s_init_service: stub, nothing opened", SVC);
	return 0;
}

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
	    "every request fails", SVC, lstnr_id, SB_LENGTH);
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
