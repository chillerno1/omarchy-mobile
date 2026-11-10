// SPDX-License-Identifier: MIT
/*
 * fakehal: a tiny stand-in for fingerprint.betterlife.so, for testing the
 * bridge's protocol engine on the build host (no phone, no trusted app). It
 * exports the same HMI symbol and the same libhardware fingerprint 2.1
 * interface as the real module, and simulates enrol/authenticate/enumerate/
 * remove by calling the notify callback from a background thread (so CANCEL
 * and a client disconnect can interrupt an operation).
 *
 * This is OUR code (not a vendor binary): it may be committed. It is built
 * only by the Makefile's "test" target and loaded only via the bridge's
 * --module option.
 *
 * Behaviour knobs, through the environment:
 *   FAKEHAL_ENROLL_STEPS   enrol progress steps before done (default 3)
 *   FAKEHAL_ENROLL_ID      the id a completed enrol reports (default 7)
 *   FAKEHAL_MATCH_ID       authenticate reports MATCH with this id; 0 means
 *                          NOMATCH (default 7)
 *   FAKEHAL_LIST           space-separated enrolled ids LIST returns
 *                          (default "7")
 *   FAKEHAL_STEP_MS        delay between simulated messages (default 150)
 *   FAKEHAL_LOCKOUT        if 1, authenticate reports LOCKOUT (error 7)
 *   FAKEHAL_ENUM_HANG      if 1, enumerate never ends: the ids come with a
 *                          remaining count one too high, so none reaches 0
 *                          (with no ids, nothing comes at all)
 *   FAKEHAL_REMOVE_HANG    if 1, remove never answers
 *   FAKEHAL_REMOVE_ID      if set, remove reports this id removed instead
 *   FAKEHAL_ENROLL_ERROR   if set, enrol reports this error after its first
 *                          progress step, and ends
 *
 * enroll() writes "fakehal: enroll timeout_sec N" to stderr, so a test sees
 * the timeout the bridge passed. It checks the token the way the Saga's
 * bd_enroll does, in its order: a zero timestamp ("hat is null") or a
 * challenge that is not the last pre_enroll's notifies ERROR 2 and returns
 * 0; a version other than 0 notifies ERROR 2 and returns -93.
 */

#define _GNU_SOURCE
#define OMAMOBILE_FP_HAL_NO_START
#include "../halhost/omamobile-fp-hal.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct fake_device {
	struct fingerprint_device_t dev;
	fingerprint_notify_t notify;
	pthread_t worker;
	volatile int cancel;
	volatile int busy;
	int job;		/* 1 enroll, 2 auth, 3 enumerate, 4 remove */
	uint32_t remove_fid;
	uint64_t challenge;	/* the last pre_enroll's */
};

static int env_int(const char *name, int dflt)
{
	const char *v = getenv(name);
	return v && *v ? atoi(v) : dflt;
}

static void nap(void)
{
	int ms = env_int("FAKEHAL_STEP_MS", 150);
	struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };

	nanosleep(&ts, NULL);
}

static void emit(struct fake_device *fd, const fingerprint_msg_t *m)
{
	if (fd->notify)
		fd->notify(m);
}

static void *worker_main(void *arg)
{
	struct fake_device *fd = arg;
	fingerprint_msg_t m;

	if (fd->job == 1) {		/* enroll */
		int steps = env_int("FAKEHAL_ENROLL_STEPS", 3);
		int id = env_int("FAKEHAL_ENROLL_ID", 7);
		int err = env_int("FAKEHAL_ENROLL_ERROR", 0);

		for (int s = steps; s >= 0 && !fd->cancel; s--) {
			nap();
			if (fd->cancel)
				break;
			memset(&m, 0, sizeof(m));
			m.type = FINGERPRINT_ACQUIRED;
			m.data.acquired.acquired_info = FP_ACQUIRED_GOOD;
			emit(fd, &m);

			memset(&m, 0, sizeof(m));
			m.type = FINGERPRINT_TEMPLATE_ENROLLING;
			m.data.enroll.finger.fid = id;
			m.data.enroll.samples_remaining = s;
			emit(fd, &m);
			if (err) {
				memset(&m, 0, sizeof(m));
				m.type = FINGERPRINT_ERROR;
				m.data.error.error = err;
				emit(fd, &m);
				fd->busy = 0;
				return NULL;
			}
		}
		if (fd->cancel) {
			memset(&m, 0, sizeof(m));
			m.type = FINGERPRINT_ERROR;
			m.data.error.error = FP_ERROR_CANCELED;
			emit(fd, &m);
		}
	} else if (fd->job == 2) {	/* authenticate */
		int match = env_int("FAKEHAL_MATCH_ID", 7);

		nap();
		if (!fd->cancel && env_int("FAKEHAL_LOCKOUT", 0)) {
			memset(&m, 0, sizeof(m));
			m.type = FINGERPRINT_ERROR;
			m.data.error.error = FP_ERROR_LOCKOUT;
			emit(fd, &m);
			fd->busy = 0;
			return NULL;
		}
		if (!fd->cancel) {
			memset(&m, 0, sizeof(m));
			m.type = FINGERPRINT_ACQUIRED;
			m.data.acquired.acquired_info = FP_ACQUIRED_GOOD;
			emit(fd, &m);
		}
		nap();
		if (!fd->cancel) {
			memset(&m, 0, sizeof(m));
			m.type = FINGERPRINT_AUTHENTICATED;
			m.data.authenticated.finger.fid = match;	/* 0 => NOMATCH */
			emit(fd, &m);
		}
		if (fd->cancel) {
			memset(&m, 0, sizeof(m));
			m.type = FINGERPRINT_ERROR;
			m.data.error.error = FP_ERROR_CANCELED;
			emit(fd, &m);
		}
	} else if (fd->job == 3) {	/* enumerate */
		const char *list = getenv("FAKEHAL_LIST");
		char buf[128];
		int ids[32], n = 0;
		char *tok, *save = NULL;

		strncpy(buf, list && *list ? list : "7", sizeof(buf) - 1);
		buf[sizeof(buf) - 1] = '\0';
		for (tok = strtok_r(buf, " ", &save); tok && n < 32; tok = strtok_r(NULL, " ", &save))
			ids[n++] = atoi(tok);
		int hang = env_int("FAKEHAL_ENUM_HANG", 0) ? 1 : 0;

		nap();
		if (n == 0 && !hang) {
			memset(&m, 0, sizeof(m));
			m.type = FINGERPRINT_TEMPLATE_ENUMERATING;
			m.data.enumerated.finger.fid = 0;
			m.data.enumerated.remaining_templates = 0;
			emit(fd, &m);
		}
		for (int i = 0; i < n; i++) {
			memset(&m, 0, sizeof(m));
			m.type = FINGERPRINT_TEMPLATE_ENUMERATING;
			m.data.enumerated.finger.fid = ids[i];
			m.data.enumerated.remaining_templates = n - 1 - i + hang;
			emit(fd, &m);
		}
	} else if (fd->job == 4 && !env_int("FAKEHAL_REMOVE_HANG", 0)) {	/* remove */
		nap();
		memset(&m, 0, sizeof(m));
		m.type = FINGERPRINT_TEMPLATE_REMOVED;
		m.data.removed.finger.fid = env_int("FAKEHAL_REMOVE_ID", (int)fd->remove_fid);
		m.data.removed.remaining_templates = 0;
		emit(fd, &m);
	}
	fd->busy = 0;
	return NULL;
}

static void join_worker(struct fake_device *fd)
{
	if (fd->busy || fd->worker) {
		pthread_join(fd->worker, NULL);
		fd->worker = 0;
	}
}

static int start_job(struct fake_device *fd, int job)
{
	join_worker(fd);
	fd->cancel = 0;
	fd->busy = 1;
	fd->job = job;
	if (pthread_create(&fd->worker, NULL, worker_main, fd)) {
		fd->busy = 0;
		return -1;
	}
	return 0;
}

static int fake_set_notify(struct fingerprint_device_t *dev, fingerprint_notify_t cb)
{
	((struct fake_device *)dev)->notify = cb;
	return 0;
}

static uint64_t fake_pre_enroll(struct fingerprint_device_t *dev)
{
	struct fake_device *fd = (struct fake_device *)dev;

	fd->challenge = (uint64_t)time(NULL);
	return fd->challenge;
}

/* the vendor's refusal: a log line, ERROR 2 through notify, then RET */
static int refuse(struct fake_device *fd, const char *why, int ret)
{
	fingerprint_msg_t m;

	(void)!write(2, why, strlen(why));
	memset(&m, 0, sizeof(m));
	m.type = FINGERPRINT_ERROR;
	m.data.error.error = FP_ERROR_UNABLE_TO_PROCESS;
	emit(fd, &m);
	return ret;
}

static int fake_enroll(struct fingerprint_device_t *dev, const hw_auth_token_t *hat,
		       uint32_t gid, uint32_t to)
{
	char line[64];
	int n;

	(void)gid;
	n = snprintf(line, sizeof(line), "fakehal: enroll timeout_sec %u\n", to);
	if (n > 0)
		(void)!write(2, line, n);
	if (!hat || !hat->timestamp)
		return refuse((struct fake_device *)dev, "fakehal: error: hat is null\n", 0);
	if (hat->challenge != ((struct fake_device *)dev)->challenge)
		return refuse((struct fake_device *)dev, "fakehal: error: challenge not match\n", 0);
	if (hat->version != 0)
		return refuse((struct fake_device *)dev, "fakehal: error: invalid hat->version\n", -93);
	return start_job((struct fake_device *)dev, 1);
}

static int fake_post_enroll(struct fingerprint_device_t *dev) { (void)dev; return 0; }
static uint64_t fake_get_auth_id(struct fingerprint_device_t *dev) { (void)dev; return 0x1234; }

static int fake_cancel(struct fingerprint_device_t *dev)
{
	((struct fake_device *)dev)->cancel = 1;
	return 0;
}

static int fake_enumerate(struct fingerprint_device_t *dev)
{
	return start_job((struct fake_device *)dev, 3);
}

static int fake_remove(struct fingerprint_device_t *dev, uint32_t gid, uint32_t fid)
{
	struct fake_device *fd = (struct fake_device *)dev;

	(void)gid;
	fd->remove_fid = fid;
	return start_job(fd, 4);
}

static int fake_set_active_group(struct fingerprint_device_t *dev, uint32_t gid, const char *path)
{
	(void)dev; (void)gid; (void)path;
	return 0;
}

static int fake_authenticate(struct fingerprint_device_t *dev, uint64_t oid, uint32_t gid)
{
	(void)oid; (void)gid;
	return start_job((struct fake_device *)dev, 2);
}

static int fake_close(struct hw_device_t *device)
{
	struct fake_device *fd = (struct fake_device *)device;

	fd->cancel = 1;
	join_worker(fd);
	free(fd);
	return 0;
}

static int fake_open(const struct hw_module_t *module, const char *id,
		     struct hw_device_t **device)
{
	struct fake_device *fd;

	(void)id;
	fd = calloc(1, sizeof(*fd));
	if (!fd)
		return -1;
	fd->dev.common.tag = HARDWARE_DEVICE_TAG;
	fd->dev.common.version = FINGERPRINT_MODULE_API_VERSION_2_1;
	fd->dev.common.module = (struct hw_module_t *)module;
	fd->dev.common.close = fake_close;
	fd->dev.set_notify = fake_set_notify;
	fd->dev.pre_enroll = fake_pre_enroll;
	fd->dev.enroll = fake_enroll;
	fd->dev.post_enroll = fake_post_enroll;
	fd->dev.get_authenticator_id = fake_get_auth_id;
	fd->dev.cancel = fake_cancel;
	fd->dev.enumerate = fake_enumerate;
	fd->dev.remove = fake_remove;
	fd->dev.set_active_group = fake_set_active_group;
	fd->dev.authenticate = fake_authenticate;
	*device = &fd->dev.common;
	return 0;
}

static struct hw_module_methods_t fake_methods = { .open = fake_open };

__attribute__((visibility("default")))
struct hw_module_t HMI = {
	.tag = HARDWARE_MODULE_TAG,
	.module_api_version = FINGERPRINT_MODULE_API_VERSION_2_1,
	.hal_api_version = 0,
	.id = FINGERPRINT_HARDWARE_MODULE_ID,
	.name = "fakehal (test)",
	.author = "omarchy-mobile",
	.methods = &fake_methods,
};
