/* SPDX-License-Identifier: MIT */
/*
 * omamobile-fp-hal.h: the Solana Saga's (ingot) fingerprint HAL module ABI
 * and bionic start-up, shared by the HAL host (halhost/) and the bridge
 * (bridge/). Both programs load /vendor/lib64/hw/fingerprint.betterlife.so
 * straight into their own process and drive it, without binder or
 * hwservicemanager.
 *
 * The module is a classic libhardware module (module API 2.1). As
 * libhardware's hw_get_module() would, a client dlopen()s it, takes HMI,
 * checks the tag and id, and records the dlopen handle in hw_module_t.dso.
 * Layouts below are AOSP's hardware.h/fingerprint.h on LP64, checked against
 * the module (disassembly, 2026-11): open fills tag 'HWDT', version 0x201,
 * module at +8, close at +0x70, set_notify +0x80 ... authenticate +0xc8, and
 * set_notify stores the callback at +0x78; its message builder puts the type
 * at +0, the union at +8 (fingerprint_enroll_t holds a uint64_t), the auth
 * token at +0x10.
 *
 * These programs are bionic executables built without Android's build system:
 * _start hands the arguments to __libc_init() as bionic's crtbegin does.
 * fingerprint/ingot/Makefile builds them against the chroot's libc and libdl.
 */

#ifndef OMAMOBILE_FP_HAL_H
#define OMAMOBILE_FP_HAL_H

#include <stddef.h>
#include <stdint.h>

/* --- bionic start-up ---
 *
 * Only the executables (the HAL host, the bridge) need an entry point. A
 * shared object that includes this header for the ABI alone (the test fake
 * HAL) defines OMAMOBILE_FP_HAL_NO_START first. */

#ifndef OMAMOBILE_FP_HAL_NO_START

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

__attribute__((used, noreturn)) static void omamobile_start_main(void *raw_args)
{
	__libc_init(raw_args, NULL, main, &structors);
}

__asm__(".text\n"
	".global _start\n"
	".type _start, %function\n"
	"_start:\n"
	"	mov x0, sp\n"
	"	b omamobile_start_main\n");

#endif /* OMAMOBILE_FP_HAL_NO_START */

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

/* fingerprint.h FingerprintError (HAL 2.1): the module reports these as the
 * message's error code. 7 is LOCKOUT; >= 1000 is vendor. */
enum {
	FP_ERROR_HW_UNAVAILABLE = 1,
	FP_ERROR_UNABLE_TO_PROCESS = 2,
	FP_ERROR_TIMEOUT = 3,
	FP_ERROR_NO_SPACE = 4,
	FP_ERROR_CANCELED = 5,
	FP_ERROR_UNABLE_TO_REMOVE = 6,
	FP_ERROR_LOCKOUT = 7,
};

/* fingerprint.h FingerprintAcquiredInfo (HAL 2.1), 0-based: GOOD is 0. The
 * libfprint driver and the Pixel bridge speak the AIDL enumeration, 1-based
 * (GOOD is 1); the bridge translates (see map_acquired_2_1_to_aidl). */
enum {
	FP_ACQUIRED_GOOD = 0,
	FP_ACQUIRED_PARTIAL = 1,
	FP_ACQUIRED_INSUFFICIENT = 2,
	FP_ACQUIRED_IMAGER_DIRTY = 3,
	FP_ACQUIRED_TOO_SLOW = 4,
	FP_ACQUIRED_TOO_FAST = 5,
	FP_ACQUIRED_VENDOR = 6,
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

#define OMAMOBILE_FP_MODULE_PATH "/vendor/lib64/hw/fingerprint.betterlife.so"

#endif /* OMAMOBILE_FP_HAL_H */
