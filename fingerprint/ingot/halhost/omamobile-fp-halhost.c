// SPDX-License-Identifier: MIT
/*
 * omamobile-fp-halhost: loads the Solana Saga's fingerprint HAL module
 * (/vendor/lib64/hw/fingerprint.betterlife.so) straight into this process
 * and drives it, without binder or hwservicemanager.
 *
 *   omamobile-fp-halhost [--seconds N] [--group GID PATH] COMMAND
 *     open                      open the device, wait N seconds (10), close
 *     enumerate                 enumerate, print what is reported
 *     set-active-group GID PATH set_active_group
 *     get-authenticator-id      print the authenticator id
 *     pre-enroll                pre_enroll (print the challenge), post_enroll
 *     authenticate [--seconds N] authenticate(operation_id 0, gid 0) for N s,
 *                               print messages, cancel. Writes nothing.
 *
 * Every command opens the device first: the HAL's open is what loads the
 * btlap64 trusted application and reads the sensor's chip id, so "open" is
 * the test on its own. --group calls set_active_group right after open.
 * After the command the host waits N seconds (default 10 for open, 3 for
 * the others) and prints every message the HAL sends, then closes the
 * device. Exit status: 0 when every HAL call returned success.
 *
 * pre-enroll and authenticate are for diagnosis without the bridge: neither
 * writes a template (pre-enroll is paired with post_enroll and no enroll;
 * authenticate is cancelled). The ABI and bionic start-up live in
 * omamobile-fp-hal.h, shared with the bridge.
 */

#define _GNU_SOURCE
#include "omamobile-fp-hal.h"

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* --- output --- */

#define MODULE_PATH	OMAMOBILE_FP_MODULE_PATH

static pthread_mutex_t out_lock = PTHREAD_MUTEX_INITIALIZER;
static struct timespec t0;

__attribute__((format(printf, 1, 2)))
static void out(const char *fmt, ...)
{
	struct timespec now;
	char buf[1024];
	va_list ap;
	long ms;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	clock_gettime(CLOCK_MONOTONIC, &now);
	ms = (now.tv_sec - t0.tv_sec) * 1000 +
	     (now.tv_nsec - t0.tv_nsec) / 1000000;
	pthread_mutex_lock(&out_lock);
	printf("[%5ld.%03ld] %s\n", ms / 1000, ms % 1000, buf);
	fflush(stdout);
	pthread_mutex_unlock(&out_lock);
}

static const char *error_name(int e)
{
	switch (e) {
	case 1: return "HW_UNAVAILABLE";
	case 2: return "UNABLE_TO_PROCESS";
	case 3: return "TIMEOUT";
	case 4: return "NO_SPACE";
	case 5: return "CANCELED";
	case 6: return "UNABLE_TO_REMOVE";
	case 7: return "LOCKOUT";
	default: return e >= 1000 ? "VENDOR" : "?";
	}
}

static const char *acquired_name(int a)
{
	switch (a) {
	case 0: return "GOOD";
	case 1: return "PARTIAL";
	case 2: return "INSUFFICIENT";
	case 3: return "IMAGER_DIRTY";
	case 4: return "TOO_SLOW";
	case 5: return "TOO_FAST";
	case 6: return "DETECTED";
	default: return a >= 1000 ? "VENDOR" : "?";
	}
}

static uint64_t be64(uint64_t v) { return __builtin_bswap64(v); }
static uint32_t be32(uint32_t v) { return __builtin_bswap32(v); }

static void on_notify(const fingerprint_msg_t *msg)
{
	const hw_auth_token_t *hat;

	if (!msg) {
		out("notify: NULL message");
		return;
	}
	switch (msg->type) {
	case FINGERPRINT_ERROR:
		out("notify: ERROR %d %s", msg->data.error.error,
		    error_name(msg->data.error.error));
		break;
	case FINGERPRINT_ACQUIRED:
		out("notify: ACQUIRED %d %s", msg->data.acquired.acquired_info,
		    acquired_name(msg->data.acquired.acquired_info));
		break;
	case FINGERPRINT_TEMPLATE_ENROLLING:
		out("notify: TEMPLATE_ENROLLING gid %u fid %u remaining %u "
		    "msg 0x%llx", msg->data.enroll.finger.gid,
		    msg->data.enroll.finger.fid,
		    msg->data.enroll.samples_remaining,
		    (unsigned long long)msg->data.enroll.msg);
		break;
	case FINGERPRINT_TEMPLATE_REMOVED:
		out("notify: TEMPLATE_REMOVED gid %u fid %u remaining %u",
		    msg->data.removed.finger.gid, msg->data.removed.finger.fid,
		    msg->data.removed.remaining_templates);
		break;
	case FINGERPRINT_AUTHENTICATED:
		hat = &msg->data.authenticated.hat;
		out("notify: AUTHENTICATED gid %u fid %u (fid 0: no match)",
		    msg->data.authenticated.finger.gid,
		    msg->data.authenticated.finger.fid);
		out("  hat: version %u challenge 0x%llx user 0x%llx "
		    "authenticator 0x%llx type 0x%x timestamp %llu",
		    hat->version, (unsigned long long)hat->challenge,
		    (unsigned long long)hat->user_id,
		    (unsigned long long)hat->authenticator_id,
		    be32(hat->authenticator_type),
		    (unsigned long long)be64(hat->timestamp));
		break;
	case FINGERPRINT_TEMPLATE_ENUMERATING:
		out("notify: TEMPLATE_ENUMERATING gid %u fid %u remaining %u",
		    msg->data.enumerated.finger.gid,
		    msg->data.enumerated.finger.fid,
		    msg->data.enumerated.remaining_templates);
		break;
	default:
		out("notify: unknown type %d", msg->type);
		break;
	}
}

/* --- main --- */

static void usage(void)
{
	fprintf(stderr,
		"usage: omamobile-fp-halhost [--seconds N] [--group GID PATH] "
		"COMMAND\n"
		"  open                       open, wait, close (the HAL's "
		"init: TA load, chip id)\n"
		"  enumerate                  report the enrolled templates\n"
		"  set-active-group GID PATH  select the user's template "
		"store\n"
		"  get-authenticator-id       print the authenticator id\n"
		"  pre-enroll                 pre_enroll (challenge), post_enroll\n"
		"  authenticate               authenticate(0, 0) for N s, cancel\n");
}

static int parse_u32(const char *s, uint32_t *v)
{
	char *end;
	unsigned long n;

	errno = 0;
	n = strtoul(s, &end, 0);
	if (errno || end == s || *end || n > UINT32_MAX)
		return -1;
	*v = (uint32_t)n;
	return 0;
}

static void wait_seconds(int seconds)
{
	struct timespec ts = { .tv_sec = seconds };

	if (seconds <= 0)
		return;
	out("waiting %d s for messages", seconds);
	while (nanosleep(&ts, &ts) && errno == EINTR)
		;
}

static int set_group(struct fingerprint_device_t *dev, uint32_t gid,
		     const char *path)
{
	int ret;

	out("set_active_group(%u, \"%s\")", gid, path);
	ret = dev->set_active_group(dev, gid, path);
	out("set_active_group: %d", ret);
	return ret;
}

int main(int argc, char **argv, char **envp)
{
	const char *cmd, *group_path = NULL, *cmd_path = NULL;
	struct fingerprint_device_t *fp;
	struct hw_device_t *device = NULL;
	struct hw_module_t *module;
	uint32_t group_gid = 0, cmd_gid = 0;
	int seconds = -1, ret, failed = 0;
	void *dso;
	int i;

	(void)envp;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 1; i < argc && !strncmp(argv[i], "--", 2); i++) {
		if (!strcmp(argv[i], "--seconds") && i + 1 < argc) {
			seconds = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--group") && i + 2 < argc) {
			if (parse_u32(argv[i + 1], &group_gid)) {
				usage();
				return 2;
			}
			group_path = argv[i + 2];
			i += 2;
		} else {
			usage();
			return 2;
		}
	}
	if (i >= argc) {
		usage();
		return 2;
	}
	cmd = argv[i++];
	if (!strcmp(cmd, "set-active-group")) {
		if (argc - i != 2 || parse_u32(argv[i], &cmd_gid)) {
			usage();
			return 2;
		}
		cmd_path = argv[i + 1];
	} else if (strcmp(cmd, "open") && strcmp(cmd, "enumerate") &&
		   strcmp(cmd, "get-authenticator-id") &&
		   strcmp(cmd, "pre-enroll") && strcmp(cmd, "authenticate")) {
		fprintf(stderr, "omamobile-fp-halhost: unknown command %s "
			"(enroll and remove are not implemented; use the "
			"bridge)\n", cmd);
		usage();
		return 2;
	} else if (i != argc) {
		usage();
		return 2;
	}
	if (seconds < 0)
		seconds = strcmp(cmd, "open") ? 3 : 10;

	out("dlopen %s", MODULE_PATH);
	dso = dlopen(MODULE_PATH, RTLD_NOW);
	if (!dso) {
		out("dlopen failed: %s", dlerror());
		return 1;
	}
	module = dlsym(dso, HAL_MODULE_INFO_SYM_AS_STR);
	if (!module) {
		out("dlsym(HMI) failed: %s", dlerror());
		return 1;
	}
	out("HMI: tag 0x%08x module api 0x%04x hal api 0x%04x id \"%s\" "
	    "name \"%s\" author \"%s\"", module->tag,
	    module->module_api_version, module->hal_api_version,
	    module->id ? module->id : "(null)",
	    module->name ? module->name : "(null)",
	    module->author ? module->author : "(null)");
	if (module->tag != HARDWARE_MODULE_TAG || !module->id ||
	    strcmp(module->id, FINGERPRINT_HARDWARE_MODULE_ID) ||
	    !module->methods || !module->methods->open) {
		out("not a fingerprint hw_module_t");
		return 1;
	}
	module->dso = dso;	/* as hw_get_module() does */

	out("open(\"%s\")", FINGERPRINT_HARDWARE_MODULE_ID);
	ret = module->methods->open(module, FINGERPRINT_HARDWARE_MODULE_ID,
				    &device);
	out("open: %d, device %p", ret, (void *)device);
	if (ret || !device)
		return 1;
	out("device: tag 0x%08x version 0x%x module %p", device->tag,
	    device->version, (void *)device->module);
	if (device->tag != HARDWARE_DEVICE_TAG ||
	    device->version != FINGERPRINT_MODULE_API_VERSION_2_1) {
		out("unexpected device tag or version, not touching it");
		return 1;
	}
	fp = (struct fingerprint_device_t *)device;

	ret = fp->set_notify(fp, on_notify);
	out("set_notify: %d", ret);
	failed |= ret != 0;

	if (group_path)
		failed |= set_group(fp, group_gid, group_path) != 0;

	if (!strcmp(cmd, "enumerate")) {
		out("enumerate()");
		ret = fp->enumerate(fp);
		out("enumerate: %d", ret);
		failed |= ret != 0;
	} else if (!strcmp(cmd, "set-active-group")) {
		failed |= set_group(fp, cmd_gid, cmd_path) != 0;
	} else if (!strcmp(cmd, "get-authenticator-id")) {
		out("get_authenticator_id()");
		out("get_authenticator_id: 0x%016llx",
		    (unsigned long long)fp->get_authenticator_id(fp));
	} else if (!strcmp(cmd, "pre-enroll")) {
		uint64_t challenge;

		out("pre_enroll()");
		challenge = fp->pre_enroll(fp);
		out("pre_enroll: challenge 0x%016llx",
		    (unsigned long long)challenge);
		out("post_enroll()");
		ret = fp->post_enroll(fp);
		out("post_enroll: %d", ret);
		failed |= ret != 0;
	} else if (!strcmp(cmd, "authenticate")) {
		out("authenticate(operation_id 0, gid 0)");
		ret = fp->authenticate(fp, 0, 0);
		out("authenticate: %d", ret);
		failed |= ret != 0;
		wait_seconds(seconds);
		out("cancel()");
		ret = fp->cancel(fp);
		out("cancel: %d", ret);
		failed |= ret != 0;
		seconds = 1;	/* brief drain for the CANCELED message */
	}

	wait_seconds(seconds);

	out("close()");
	ret = device->close(device);
	out("close: %d", ret);
	failed |= ret != 0;
	return failed ? 1 : 0;
}
