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
 *
 * Every command opens the device first: the HAL's open is what loads the
 * btlap64 trusted application and reads the sensor's chip id, so "open" is
 * the test on its own. --group calls set_active_group right after open.
 * After the command the host waits N seconds (default 10 for open, 3 for
 * the others) and prints every message the HAL sends, then closes the
 * device. Exit status: 0 when every HAL call returned success.
 *
 * The module is a classic libhardware module (module API 2.1). As
 * libhardware's hw_get_module() would, the host dlopen()s it, takes HMI,
 * checks the tag and id, and records the dlopen handle in hw_module_t.dso.
 * Layouts below are AOSP's hardware.h/fingerprint.h on LP64, checked
 * against the module: its open fills tag 'HWDT', version 0x201, module at
 * +8, close at +0x70, set_notify +0x80 ... authenticate +0xc8, and
 * set_notify stores the callback at +0x78; its message builder puts the
 * type at +0, the union at +8 (fingerprint_enroll_t holds a uint64_t), the
 * auth token at +0x10.
 *
 * A bionic executable built without Android's build system: _start hands
 * the arguments to __libc_init() as bionic's crtbegin does.
 * fingerprint/ingot/Makefile builds it against the chroot's libc and libdl.
 */

#define _GNU_SOURCE
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

/* --- bionic start-up --- */

typedef struct {
	void (**preinit_array)(void);
	void (**init_array)(void);
	void (**fini_array)(void);
	size_t preinit_array_count;
	size_t init_array_count;
	size_t fini_array_count;
} structors_array_t;

extern void __libc_init(void *raw_args, void (*onexit)(void),
			int (*slingshot)(int, char **, char **),
			structors_array_t const *const structors)
	__attribute__((noreturn));
int main(int argc, char **argv, char **envp);

/* The linker runs DT_INIT_ARRAY itself for a dynamic executable. */
static const structors_array_t structors;

__attribute__((used, noreturn)) void omamobile_start_main(void *raw_args)
{
	__libc_init(raw_args, NULL, main, &structors);
}

__asm__(".text\n"
	".global _start\n"
	".type _start, %function\n"
	"_start:\n"
	"	mov x0, sp\n"
	"	b omamobile_start_main\n");

/* --- hardware/hardware.h, hardware/fingerprint.h (LP64) --- */

#define MAKE_TAG_CONSTANT(A, B, C, D) \
	(((A) << 24) | ((B) << 16) | ((C) << 8) | (D))
#define HARDWARE_MODULE_TAG	MAKE_TAG_CONSTANT('H', 'W', 'M', 'T')
#define HARDWARE_DEVICE_TAG	MAKE_TAG_CONSTANT('H', 'W', 'D', 'T')
#define HAL_MODULE_INFO_SYM_AS_STR	"HMI"
#define FINGERPRINT_HARDWARE_MODULE_ID	"fingerprint"
#define FINGERPRINT_MODULE_API_VERSION_2_1	0x0201

struct hw_module_t;
struct hw_device_t;

struct hw_module_methods_t {
	int (*open)(const struct hw_module_t *module, const char *id,
		    struct hw_device_t **device);
};

struct hw_module_t {
	uint32_t tag;
	uint16_t module_api_version;
	uint16_t hal_api_version;
	const char *id;
	const char *name;
	const char *author;
	struct hw_module_methods_t *methods;
	void *dso;
	uint64_t reserved[32 - 7];
};

struct hw_device_t {
	uint32_t tag;
	uint32_t version;
	struct hw_module_t *module;
	uint64_t reserved[12];
	int (*close)(struct hw_device_t *device);
};

_Static_assert(sizeof(struct hw_module_t) == 248, "hw_module_t (HMI is 248)");
_Static_assert(__builtin_offsetof(struct hw_device_t, close) == 0x70,
	       "hw_device_t.close");

enum {
	FINGERPRINT_ERROR = -1,
	FINGERPRINT_ACQUIRED = 1,
	FINGERPRINT_TEMPLATE_ENROLLING = 3,
	FINGERPRINT_TEMPLATE_REMOVED = 4,
	FINGERPRINT_AUTHENTICATED = 5,
	FINGERPRINT_TEMPLATE_ENUMERATING = 6,
};

typedef struct {
	uint32_t gid;
	uint32_t fid;
} fingerprint_finger_id_t;

typedef struct __attribute__((packed)) {
	uint8_t version;
	uint64_t challenge;
	uint64_t user_id;
	uint64_t authenticator_id;
	uint32_t authenticator_type;	/* network order */
	uint64_t timestamp;		/* network order */
	uint8_t hmac[32];
} hw_auth_token_t;

_Static_assert(sizeof(hw_auth_token_t) == 69, "hw_auth_token_t");

typedef struct {
	int32_t type;
	union {
		struct { int32_t error; } error;
		struct {
			fingerprint_finger_id_t finger;
			uint32_t samples_remaining;
			uint64_t msg;
		} enroll;
		struct {
			fingerprint_finger_id_t finger;
			uint32_t remaining_templates;
		} enumerated;
		struct {
			fingerprint_finger_id_t finger;
			uint32_t remaining_templates;
		} removed;
		struct { int32_t acquired_info; } acquired;
		struct {
			fingerprint_finger_id_t finger;
			hw_auth_token_t hat;
		} authenticated;
	} data;
} fingerprint_msg_t;

_Static_assert(__builtin_offsetof(fingerprint_msg_t, data) == 8,
	       "fingerprint_msg_t.data");
_Static_assert(__builtin_offsetof(fingerprint_msg_t, data.authenticated.hat)
	       == 0x10, "fingerprint_msg_t hat");

typedef void (*fingerprint_notify_t)(const fingerprint_msg_t *msg);

struct fingerprint_device_t {
	struct hw_device_t common;
	fingerprint_notify_t notify;
	int (*set_notify)(struct fingerprint_device_t *dev,
			  fingerprint_notify_t notify);
	uint64_t (*pre_enroll)(struct fingerprint_device_t *dev);
	int (*enroll)(struct fingerprint_device_t *dev,
		      const hw_auth_token_t *hat, uint32_t gid,
		      uint32_t timeout_sec);
	int (*post_enroll)(struct fingerprint_device_t *dev);
	uint64_t (*get_authenticator_id)(struct fingerprint_device_t *dev);
	int (*cancel)(struct fingerprint_device_t *dev);
	int (*enumerate)(struct fingerprint_device_t *dev);
	int (*remove)(struct fingerprint_device_t *dev, uint32_t gid,
		      uint32_t fid);
	int (*set_active_group)(struct fingerprint_device_t *dev,
				uint32_t gid, const char *store_path);
	int (*authenticate)(struct fingerprint_device_t *dev,
			    uint64_t operation_id, uint32_t gid);
	void *reserved[4];
};

_Static_assert(__builtin_offsetof(struct fingerprint_device_t, notify)
	       == 0x78, "fingerprint_device_t.notify");
_Static_assert(__builtin_offsetof(struct fingerprint_device_t, authenticate)
	       == 0xc8, "fingerprint_device_t.authenticate");

/* --- output --- */

#define MODULE_PATH	"/vendor/lib64/hw/fingerprint.betterlife.so"

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
		"  get-authenticator-id       print the authenticator id\n");
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
		   strcmp(cmd, "get-authenticator-id")) {
		fprintf(stderr, "omamobile-fp-halhost: unknown command %s "
			"(pre-enroll, enroll, authenticate and remove are "
			"not implemented)\n", cmd);
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
	}

	wait_seconds(seconds);

	out("close()");
	ret = device->close(device);
	out("close: %d", ret);
	failed |= ret != 0;
	return failed ? 1 : 0;
}
