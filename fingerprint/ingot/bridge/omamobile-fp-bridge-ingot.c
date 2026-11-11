// SPDX-License-Identifier: MIT
/*
 * omamobile-fp-bridge-ingot: hosts the Solana Saga's (ingot) vendor
 * fingerprint HAL module (/vendor/lib64/hw/fingerprint.betterlife.so,
 * libhardware fingerprint 2.1) in-process and serves the Omarchy Mobile
 * fingerprint line protocol on a Unix socket, so enrolment and verification
 * work through fprintd. It is the Saga's counterpart to the Pixel's
 * fingerprint/bridge/omamobile-fp-bridge.c; the libfprint driver
 * (packages/libfprint/omamobile-udfps.c) and the CLI
 * (packages/omamobile-fingerprint/lib/omamobile-fp-ctl) are the clients.
 *
 *   omamobile-fp-bridge-ingot --socket PATH --state DIR [--data-path DIR]
 *                             [--module PATH] [--sid N] [--gid N]
 *                             [--enroll-timeout SEC] [--list-timeout SEC]
 *
 *   -> ENROLL | AUTH | LIST | DELETE <id> | CANCEL | RESETLOCKOUT | STATUS
 *   <- READY 0 0 0                          on connect (sensor not under the
 *                                           display: no x/y/radius)
 *      FINGER NEEDED | FINGER DOWN | FINGER UP
 *      ACQUIRED <code> <vendor>             <code>: AIDL AcquiredInfo (mapped)
 *      PROGRESS <id> <remaining>
 *      ENROLLED <id>                        ENROLL done
 *      MATCH <id> | NOMATCH                 AUTH done
 *      LIST [<id>...]                       LIST done
 *      DELETED <id>                         DELETE done
 *      LOCKOUT <ms>                         AUTH or ENROLL done; -1: unknown
 *      ERROR <code>                         the operation ended (5: canceled)
 *      OK                                   RESETLOCKOUT, STATUS done
 *
 * One operation at a time; one client at a time (a new connection replaces
 * the old one and cancels its operation). The socket is 0600.
 *
 * LIST and DELETE end when the HAL says so (an enumerate's or a remove's
 * remaining count reaching 0). A HAL that never does (some end no
 * enumerate of an empty group) must not leave the bridge busy for good, so
 * LIST and DELETE also end on CANCEL, on the client going away, and after
 * --list-timeout seconds (default 5): a LIST then answers with the ids it
 * has seen so far (none is a valid answer), a DELETE with ERROR 5 (CANCEL)
 * or ERROR 3 (the deadline), never DELETED: only the HAL confirms a removal.
 * The HAL is not told (HAL 2.1's cancel() is for enroll and authenticate).
 * Only a removal of the id asked (any, for DELETE 0: all) confirms a DELETE,
 * so a late answer to an abandoned one never confirms the next.
 *
 * --enroll-timeout is the HAL 2.1 enroll()'s timeout_sec, which bounds the
 * whole enrolment ("switches back as soon as enroll is complete ... or after
 * timeout_sec seconds", libhardware's fingerprint.h), not the wait for one
 * touch. The default is Android's own (FingerprintService: 60 s); a session
 * with a person relaying instructions passes more.
 *
 * The auth token for ENROLL (option a: no real secure storage)
 * -----------------------------------------------------------
 * The Saga's HAL 2.1 enroll (fingerprint.betterlife.so, bd_enroll) checks,
 * in the library, before touching the trusted app:
 *   - hat->timestamp != 0. Its message for a zero one is "hat is null"
 *     (bd_enroll line 231 tests the 8 bytes at offset 0x1d, the packed
 *     token's timestamp, not the pointer). It then notifies ERROR 2 and
 *     returns 0, so the client saw FINGER NEEDED, then ERROR 2;
 *   - hat->challenge == the value pre_enroll() just returned ("challenge not
 *     match" otherwise; also ERROR 2 after a return of 0);
 *   - hat->version == 0 ("invalid hat->version" otherwise, returns -93);
 *     pre_enroll() returns CLOCK_MONOTONIC tv_sec; there is no crypto on it;
 *   - hat->user_id (the Android secure id) is passed to the trusted app's
 *     secure-id check ("Android Sercure id not match" otherwise).
 * The token HMAC is NEVER verified: the library's auth-token check
 * (mngr_chk_auth_token) returns success without calling the app, and the
 * app's key (loaded at init via keymaster64, cid 222) is used only to SIGN
 * the token the app returns on a successful authenticate. So enrolment does
 * not need a gatekeeper-signed token: the bridge forges the token itself,
 * with version 0, the live pre_enroll challenge, a fixed secure id (--sid,
 * default 0) and a timestamp (ms since boot, network order, as gatekeeper
 * makes it; only its being non-zero is checked). The trusted app never
 * sees the token at enrolment: after these checks bd_enroll hands it only
 * a new template id. The vendor gatekeeper is not used, and could not
 * persist under option (a) anyway (its keymaster blobs would need the RPMB
 * and SSD listeners, which are stubs here).
 *
 * If the trusted app rejects the secure id (its stored secure id is not 0),
 * the ENROLL fails with a clear log line ("Android Sercure id not match")
 * and the tester retries with a different --sid. Nothing hangs. Careful: on
 * a secure-id mismatch bd_enroll first REMOVES ALL TEMPLATES and checks
 * again ("... and remove all fingerprints failed" if that fails), so a new
 * --sid after an enrolment erases it, as a new secure id does on Android.
 *
 * Templates live in <data-path> (set_active_group(0, <data-path>); the HAL
 * writes <data-path>/<user>.mbn). <data-path> defaults to <state>/fpdata,
 * a directory under the chroot's private /data. Nothing else is persisted.
 *
 * The ABI and bionic start-up live in ../halhost/omamobile-fp-hal.h, shared
 * with the HAL host. A bionic executable built without Android's build
 * system; fingerprint/ingot/Makefile builds it against the chroot's libc
 * and libdl.
 */

#define _GNU_SOURCE
#include "../halhost/omamobile-fp-hal.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* --- configuration --- */

static const char *socket_path;		/* --socket (required) */
static const char *state_dir;		/* --state (required) */
static const char *data_path;		/* --data-path (default <state>/fpdata) */
static const char *module_path = OMAMOBILE_FP_MODULE_PATH;	/* --module */
static uint64_t forged_sid;		/* --sid: hat->user_id for enrol */
static uint32_t active_gid;		/* --gid: set_active_group/enroll gid */
static uint32_t enroll_timeout = 60;	/* --enroll-timeout seconds */
static uint32_t list_timeout = 5;	/* --list-timeout seconds (LIST, DELETE) */

/* How long to wait for the HAL to answer a cancel before giving up. The
 * libfprint driver's own backstop is 5 s; we must answer before that. */
#define CANCEL_GRACE_MS 3000

/* --- logging (stderr, timestamped; the runner captures it) --- */

static struct timespec t0;

__attribute__((format(printf, 1, 2)))
static void say(const char *fmt, ...)
{
	struct timespec now;
	char line[640];
	va_list ap;
	long ms;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(line, sizeof(line) - 1, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if (n > (int)sizeof(line) - 2)
		n = sizeof(line) - 2;
	clock_gettime(CLOCK_MONOTONIC, &now);
	ms = (now.tv_sec - t0.tv_sec) * 1000 + (now.tv_nsec - t0.tv_nsec) / 1000000;
	{
		char out[700];
		int m = snprintf(out, sizeof(out), "[%5ld.%03ld] bridge: %.*s\n",
				 ms / 1000, ms % 1000, n, line);
		if (m > 0)
			(void)!write(2, out, m);
	}
}

static int64_t now_ms(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

/* --- callback events: the HAL's navigation thread -> the main loop ---
 *
 * The HAL reports through the notify callback, which it may call from its own
 * internal thread. We never touch the client socket or operation state from
 * there: the callback only copies the message and writes it to a self-pipe
 * the main loop reads, exactly as the Pixel bridge does. */

static int events[2] = { -1, -1 };

static void on_notify(const fingerprint_msg_t *msg)
{
	if (!msg)
		return;
	(void)!write(events[1], msg, sizeof(*msg));
}

/* --- the HAL device --- */

static void *hal_dso;
static struct fingerprint_device_t *fp;

static const char *error_name(int e)
{
	switch (e) {
	case FP_ERROR_HW_UNAVAILABLE: return "HW_UNAVAILABLE";
	case FP_ERROR_UNABLE_TO_PROCESS: return "UNABLE_TO_PROCESS";
	case FP_ERROR_TIMEOUT: return "TIMEOUT";
	case FP_ERROR_NO_SPACE: return "NO_SPACE";
	case FP_ERROR_CANCELED: return "CANCELED";
	case FP_ERROR_UNABLE_TO_REMOVE: return "UNABLE_TO_REMOVE";
	case FP_ERROR_LOCKOUT: return "LOCKOUT";
	default: return e >= 1000 ? "VENDOR" : "?";
	}
}

/*
 * The HAL reports acquired hints in the HAL-2.1 enumeration (GOOD == 0). The
 * libfprint driver and the Pixel bridge speak the AIDL enumeration
 * (GOOD == 1). Translate 2.1 -> AIDL so a Saga capture reads to libfprint
 * exactly like a Pixel one. An unknown 2.1 code passes through unchanged.
 */
static int map_acquired_2_1_to_aidl(int code)
{
	switch (code) {
	case FP_ACQUIRED_GOOD: return 1;		/* GOOD */
	case FP_ACQUIRED_PARTIAL: return 2;		/* PARTIAL */
	case FP_ACQUIRED_INSUFFICIENT: return 3;	/* INSUFFICIENT */
	case FP_ACQUIRED_IMAGER_DIRTY: return 4;	/* SENSOR_DIRTY */
	case FP_ACQUIRED_TOO_SLOW: return 5;		/* TOO_SLOW */
	case FP_ACQUIRED_TOO_FAST: return 6;		/* TOO_FAST */
	case FP_ACQUIRED_VENDOR: return 7;		/* VENDOR */
	default: return code;
	}
}

static int hal_load_open(void)
{
	struct hw_module_t *module;
	struct hw_device_t *device = NULL;
	int ret;

	say("dlopen %s", module_path);
	hal_dso = dlopen(module_path, RTLD_NOW);
	if (!hal_dso) {
		say("dlopen failed: %s", dlerror());
		return -1;
	}
	module = dlsym(hal_dso, HAL_MODULE_INFO_SYM_AS_STR);
	if (!module) {
		say("dlsym(HMI) failed: %s", dlerror());
		return -1;
	}
	if (module->tag != HARDWARE_MODULE_TAG || !module->id ||
	    strcmp(module->id, FINGERPRINT_HARDWARE_MODULE_ID) ||
	    !module->methods || !module->methods->open) {
		say("not a fingerprint hw_module_t (tag 0x%08x)", module->tag);
		return -1;
	}
	module->dso = hal_dso;		/* as hw_get_module() does */
	say("module api 0x%04x \"%s\"", module->module_api_version,
	    module->name ? module->name : "");

	ret = module->methods->open(module, FINGERPRINT_HARDWARE_MODULE_ID, &device);
	if (ret || !device) {
		say("open failed: %d (device %p)", ret, (void *)device);
		return -1;
	}
	if (device->tag != HARDWARE_DEVICE_TAG ||
	    device->version != FINGERPRINT_MODULE_API_VERSION_2_1) {
		say("unexpected device tag/version (0x%08x 0x%x)",
		    device->tag, device->version);
		return -1;
	}
	fp = (struct fingerprint_device_t *)device;

	ret = fp->set_notify(fp, on_notify);
	if (ret) {
		say("set_notify failed: %d", ret);
		return -1;
	}
	say("set_active_group(%u, \"%s\")", active_gid, data_path);
	ret = fp->set_active_group(fp, active_gid, data_path);
	if (ret) {
		say("set_active_group failed: %d", ret);
		return -1;
	}
	say("HAL open; authenticator id 0x%016llx",
	    (unsigned long long)fp->get_authenticator_id(fp));
	return 0;
}

/* --- the client socket --- */

static int listen_fd = -1, client_fd = -1;
static char client_buf[256];
static size_t client_used;

__attribute__((format(printf, 1, 2)))
static void reply(const char *fmt, ...)
{
	char line[256];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(line, sizeof(line) - 1, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if (n > (int)sizeof(line) - 2)
		n = sizeof(line) - 2;
	say("-> %.*s", n, line);
	line[n++] = '\n';
	if (client_fd >= 0 && send(client_fd, line, n, MSG_NOSIGNAL) != n) {
		close(client_fd);
		client_fd = -1;
	}
}

/* --- operations --- */

enum op { OP_NONE, OP_ENROLL, OP_AUTH, OP_LIST, OP_DELETE };
static enum op op;
static bool op_ending;		/* cancel sent, waiting for the HAL's end */
static bool ending_reply;	/* report the end as ERROR 5 (a client CANCEL) */
static int64_t op_ending_since;
static bool finger_down;	/* we have told the client FINGER DOWN */
static int32_t delete_id;	/* the id a DELETE asked to remove */
static int64_t op_since;	/* when a LIST or DELETE started */
static char pending[64];	/* a command queued while op_ending */

/* enumerate accumulates ids until remaining_templates reaches 0 */
static int32_t list_ids[32];
static int list_n;

/* LIST done: the ids the HAL has enumerated (so far) */
static void reply_list(void)
{
	char list[256];
	size_t n = 0;

	for (int i = 0; i < list_n && n < sizeof(list) - 12; i++)
		n += snprintf(list + n, sizeof(list) - n, " %d", list_ids[i]);
	list[n] = '\0';
	reply("LIST%s", list);
	op = OP_NONE;
}

/*
 * End a LIST or DELETE the HAL has not finished. WHY: "cancel" (a client's
 * CANCEL), "timeout" (--list-timeout), or NULL (the client went away: no
 * reply). A LIST answers with what it has; a DELETE fails, never DELETED.
 */
static void end_admin(const char *why)
{
	if (op != OP_LIST && op != OP_DELETE)
		return;
	if (op == OP_LIST) {
		say("LIST: no end from the HAL (%s); %d id(s) so far",
		    why ? why : "client gone", list_n);
		if (why)
			reply_list();
	} else {
		say("DELETE %d: no answer from the HAL (%s); not confirmed",
		    delete_id, why ? why : "client gone");
		if (why)
			reply("ERROR %d", strcmp(why, "timeout") ? FP_ERROR_CANCELED
							  : FP_ERROR_TIMEOUT);
	}
	op = OP_NONE;
}

static bool capturing(void)
{
	return (op == OP_ENROLL || op == OP_AUTH) && !op_ending;
}

static void op_done(void)
{
	if (finger_down) {
		reply("FINGER UP");
		finger_down = false;
	}
	if (op == OP_ENROLL) {
		fp->post_enroll(fp);	/* revoke the single-use challenge */
		/* The HAL's finger list is a cache it refreshes only on
		 * set_active_group, remove and authenticate (libBtlFpHal's
		 * sync_user_info is called with sync=0 by enumerate and never
		 * by enroll), so without this a LIST right after ENROLLED
		 * would miss the new finger until the next restart. */
		if (fp->set_active_group(fp, active_gid, data_path))
			say("set_active_group after enrol failed");
	}
	op = OP_NONE;
	op_ending = false;
	ending_reply = false;
}

/* Cancel a running capture; REPORT: answer ERROR 5 once the HAL has ended. */
static void end_capture(bool report)
{
	if (op != OP_ENROLL && op != OP_AUTH)
		return;
	ending_reply = ending_reply || report;
	if (op_ending)
		return;
	say("cancel()");
	fp->cancel(fp);
	op_ending = true;
	op_ending_since = now_ms();
}

/*
 * Forge the enrol auth token (see the file header). version 0, the live
 * pre_enroll challenge, user_id = the configured secure id, everything else
 * zero (the HMAC is never checked).
 */
static void start_enroll(void)
{
	hw_auth_token_t hat;
	uint64_t challenge;
	int ret;

	challenge = fp->pre_enroll(fp);
	say("pre_enroll: challenge 0x%016llx", (unsigned long long)challenge);

	memset(&hat, 0, sizeof(hat));
	hat.version = 0;
	hat.challenge = challenge;
	hat.user_id = forged_sid;
	{
		struct timespec boot;
		uint64_t ms = 1;

		if (!clock_gettime(CLOCK_BOOTTIME, &boot))
			ms = (uint64_t)boot.tv_sec * 1000 + boot.tv_nsec / 1000000;
		hat.timestamp = __builtin_bswap64(ms ? ms : 1);	/* network order */
	}

	say("enroll(gid %u, secure_id 0x%llx, timeout %u s)", active_gid,
	    (unsigned long long)forged_sid, enroll_timeout);
	ret = fp->enroll(fp, &hat, active_gid, enroll_timeout);
	if (ret) {
		say("enroll refused: %d (%s) — if the log shows \"Android "
		    "Sercure id not match\", retry with a different --sid",
		    ret, error_name(ret));
		fp->post_enroll(fp);
		reply("ERROR %d", ret > 0 ? ret : FP_ERROR_UNABLE_TO_PROCESS);
		return;
	}
	op = OP_ENROLL;
	reply("FINGER NEEDED");
}

static void start_auth(void)
{
	int ret;

	say("authenticate(operation_id 0, gid %u)", active_gid);
	ret = fp->authenticate(fp, 0, active_gid);
	if (ret) {
		say("authenticate refused: %d (%s)", ret, error_name(ret));
		reply("ERROR %d", ret > 0 ? ret : FP_ERROR_UNABLE_TO_PROCESS);
		return;
	}
	op = OP_AUTH;
	reply("FINGER NEEDED");
}

static void command(const char *line)
{
	int32_t id;

	say("<- %s", line);
	if (!strcmp(line, "CANCEL")) {
		pending[0] = '\0';
		if (op == OP_ENROLL || op == OP_AUTH)
			end_capture(true);
		else if (op == OP_LIST || op == OP_DELETE)
			end_admin("cancel");
		else if (op == OP_NONE)
			reply("ERROR %d", FP_ERROR_CANCELED);
		return;
	}
	if (op != OP_NONE) {
		if (op_ending && strlen(line) < sizeof(pending)) {
			strcpy(pending, line);	/* once the HAL has ended */
			return;
		}
		reply("ERROR %d", FP_ERROR_UNABLE_TO_PROCESS);
		return;
	}
	if (!strcmp(line, "ENROLL")) {
		start_enroll();
	} else if (!strcmp(line, "AUTH")) {
		start_auth();
	} else if (!strcmp(line, "LIST")) {
		list_n = 0;
		op_since = now_ms();
		if (fp->enumerate(fp) == 0)
			op = OP_LIST;
		else
			reply("ERROR %d", FP_ERROR_UNABLE_TO_PROCESS);
	} else if (sscanf(line, "DELETE %d", &id) == 1) {
		delete_id = id;
		op_since = now_ms();
		if (fp->remove(fp, active_gid, (uint32_t)id) == 0)
			op = OP_DELETE;
		else
			reply("ERROR %d", FP_ERROR_UNABLE_TO_PROCESS);
	} else if (!strcmp(line, "RESETLOCKOUT")) {
		/* No gatekeeper-signed token under option (a); the HAL clears
		 * its own timed lockout as captures succeed. */
		reply("ERROR %d", FP_ERROR_UNABLE_TO_PROCESS);
	} else if (!strcmp(line, "STATUS")) {
		reply("READY 0 0 0");
		reply("OK");
	} else {
		reply("ERROR %d", FP_ERROR_UNABLE_TO_PROCESS);
	}
}

static void hal_event(const fingerprint_msg_t *e)
{
	switch (e->type) {
	case FINGERPRINT_ACQUIRED:
		if (!capturing())
			return;
		if (!finger_down) {
			reply("FINGER DOWN");
			finger_down = true;
		}
		reply("ACQUIRED %d 0", map_acquired_2_1_to_aidl(e->data.acquired.acquired_info));
		return;
	case FINGERPRINT_TEMPLATE_ENROLLING:
		if (op != OP_ENROLL)
			return;
		reply("PROGRESS %u %u", e->data.enroll.finger.fid,
		      e->data.enroll.samples_remaining);
		if (e->data.enroll.samples_remaining == 0) {
			reply("ENROLLED %u", e->data.enroll.finger.fid);
			op_done();
		}
		return;
	case FINGERPRINT_AUTHENTICATED:
		if (op != OP_AUTH)
			return;
		if (e->data.authenticated.finger.fid != 0) {
			/* a match ends the operation */
			if (!op_ending)
				reply("MATCH %u", e->data.authenticated.finger.fid);
			else if (ending_reply)
				reply("ERROR %d", FP_ERROR_CANCELED);
			op_done();
		} else {
			/* fid 0: a non-match. The HAL keeps capturing; stop it
			 * and report NOMATCH so the client's verify completes. */
			if (!op_ending) {
				reply("NOMATCH");
				end_capture(false);
			}
		}
		return;
	case FINGERPRINT_ERROR:
		say("HAL error %d (%s)", e->data.error.error,
		    error_name(e->data.error.error));
		if (op == OP_NONE)
			return;
		if (e->data.error.error == FP_ERROR_LOCKOUT) {
			if (!op_ending)
				reply("LOCKOUT -1");
			else if (ending_reply)
				reply("ERROR %d", FP_ERROR_CANCELED);
			op_done();
			return;
		}
		/* a cancel we sent: report it only if a client asked */
		if (!op_ending || e->data.error.error != FP_ERROR_CANCELED || ending_reply)
			reply("ERROR %d", e->data.error.error);
		op_done();
		return;
	case FINGERPRINT_TEMPLATE_ENUMERATING:
		if (op != OP_LIST) {
			say("enumerated %u (remaining %u) outside a LIST: ignored",
			    e->data.enumerated.finger.fid,
			    e->data.enumerated.remaining_templates);
			return;
		}
		if (e->data.enumerated.finger.fid != 0 && list_n < (int)(sizeof(list_ids) / sizeof(list_ids[0])))
			list_ids[list_n++] = e->data.enumerated.finger.fid;
		if (e->data.enumerated.remaining_templates == 0)
			reply_list();
		return;
	case FINGERPRINT_TEMPLATE_REMOVED:
		if (op != OP_DELETE) {
			say("removed %u (remaining %u) outside a DELETE: ignored",
			    e->data.removed.finger.fid,
			    e->data.removed.remaining_templates);
			return;
		}
		if (delete_id != 0 && (int32_t)e->data.removed.finger.fid != delete_id) {
			say("removed %u (remaining %u), not the %d asked: ignored",
			    e->data.removed.finger.fid,
			    e->data.removed.remaining_templates, delete_id);
			return;
		}
		/* one or more REMOVED; complete when the HAL is done */
		if (e->data.removed.remaining_templates == 0) {
			reply("DELETED %d", delete_id);
			op = OP_NONE;
		}
		return;
	default:
		return;
	}
}

static void new_client(void)
{
	int fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);

	if (fd < 0)
		return;
	if (client_fd >= 0) {
		say("new client: dropping the old one");
		close(client_fd);
		end_capture(false);
		end_admin(NULL);
		pending[0] = '\0';
	}
	client_fd = fd;
	client_used = 0;
	reply("READY 0 0 0");
}

static void client_input(void)
{
	ssize_t n = recv(client_fd, client_buf + client_used,
			 sizeof(client_buf) - 1 - client_used, 0);
	char *line, *nl;

	if (n <= 0) {
		close(client_fd);
		client_fd = -1;
		pending[0] = '\0';
		end_capture(false);
		end_admin(NULL);
		return;
	}
	client_used += n;
	client_buf[client_used] = '\0';
	line = client_buf;
	while ((nl = strchr(line, '\n'))) {
		*nl = '\0';
		if (nl > line && nl[-1] == '\r')
			nl[-1] = '\0';
		if (*line)
			command(line);
		line = nl + 1;
	}
	client_used = strlen(line);
	memmove(client_buf, line, client_used);
	if (client_used == sizeof(client_buf) - 1)
		client_used = 0;	/* overlong line: drop it */
}

static int open_listener(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	if (strlen(socket_path) >= sizeof(addr.sun_path))
		return -1;
	strcpy(addr.sun_path, socket_path);
	unlink(socket_path);
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	umask(0077);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
	    chmod(socket_path, 0600) || listen(fd, 2)) {
		close(fd);
		return -1;
	}
	return fd;
}

/* --- shutdown --- */

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static void usage(void)
{
	say("usage: omamobile-fp-bridge-ingot --socket PATH --state DIR\n"
	    "         [--data-path DIR] [--module PATH] [--sid N] [--gid N]\n"
	    "         [--enroll-timeout SEC] [--list-timeout SEC]");
	exit(2);
}

static int mkdirs(const char *path)
{
	char tmp[512];
	size_t i, len = strlen(path);

	if (len >= sizeof(tmp))
		return -1;
	strcpy(tmp, path);
	for (i = 1; i < len; i++) {
		if (tmp[i] != '/')
			continue;
		tmp[i] = '\0';
		if (mkdir(tmp, 0700) && errno != EEXIST)
			return -1;
		tmp[i] = '/';
	}
	if (mkdir(tmp, 0700) && errno != EEXIST)
		return -1;
	return 0;
}

int main(int argc, char **argv, char **envp)
{
	static char data_default[512];
	struct sigaction sa = { .sa_handler = on_signal };

	(void)envp;
	clock_gettime(CLOCK_MONOTONIC, &t0);

	for (int i = 1; i < argc; i++) {
		const char *v = i + 1 < argc ? argv[i + 1] : NULL;

		if (!strcmp(argv[i], "--socket") && v) socket_path = v, i++;
		else if (!strcmp(argv[i], "--state") && v) state_dir = v, i++;
		else if (!strcmp(argv[i], "--data-path") && v) data_path = v, i++;
		else if (!strcmp(argv[i], "--module") && v) module_path = v, i++;
		else if (!strcmp(argv[i], "--sid") && v) forged_sid = strtoull(v, NULL, 0), i++;
		else if (!strcmp(argv[i], "--gid") && v) active_gid = (uint32_t)strtoul(v, NULL, 0), i++;
		else if (!strcmp(argv[i], "--enroll-timeout") && v) enroll_timeout = (uint32_t)strtoul(v, NULL, 0), i++;
		else if (!strcmp(argv[i], "--list-timeout") && v) list_timeout = (uint32_t)strtoul(v, NULL, 0), i++;
		else usage();
	}
	if (!socket_path || !state_dir || !enroll_timeout || !list_timeout)
		usage();
	if (!data_path) {
		snprintf(data_default, sizeof(data_default), "%s/fpdata", state_dir);
		data_path = data_default;
	}

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);

	if (mkdirs(state_dir) || mkdirs(data_path)) {
		say("cannot create %s / %s: %s", state_dir, data_path, strerror(errno));
		return 1;
	}
	if (pipe2(events, O_CLOEXEC)) {
		say("pipe: %s", strerror(errno));
		return 1;
	}
	if (hal_load_open())
		return 1;

	listen_fd = open_listener();
	if (listen_fd < 0) {
		say("cannot listen on %s: %s", socket_path, strerror(errno));
		return 1;
	}
	say("ready on %s (enroll timeout %u s, LIST/DELETE deadline %u s)",
	    socket_path, enroll_timeout, list_timeout);

	while (!stop) {
		struct pollfd fds[3] = {
			{ events[0], POLLIN, 0 },
			{ listen_fd, POLLIN, 0 },
			{ client_fd, POLLIN, 0 },
		};
		fingerprint_msg_t e;

		if (poll(fds, 3, 500) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (fds[0].revents & POLLIN &&
		    read(events[0], &e, sizeof(e)) == sizeof(e))
			hal_event(&e);
		if (fds[1].revents & POLLIN)
			new_client();
		if (client_fd >= 0 && fds[2].revents & (POLLIN | POLLHUP | POLLERR))
			client_input();

		/* a cancel the HAL never answered */
		if (op_ending && now_ms() - op_ending_since > CANCEL_GRACE_MS) {
			say("no answer to cancel; completing the operation");
			if (ending_reply)
				reply("ERROR %d", FP_ERROR_CANCELED);
			op_done();
		}
		/* a LIST or DELETE the HAL never finished */
		if ((op == OP_LIST || op == OP_DELETE) &&
		    now_ms() - op_since >= (int64_t)list_timeout * 1000)
			end_admin("timeout");
		if (op == OP_NONE && pending[0]) {
			char line[sizeof(pending)];

			strcpy(line, pending);
			pending[0] = '\0';
			command(line);
		}
	}

	say("shutting down: cancelling and closing the device");
	if (op == OP_ENROLL || op == OP_AUTH)
		fp->cancel(fp);
	if (fp)
		fp->common.close(&fp->common);	/* unloads the trusted app */
	if (listen_fd >= 0)
		unlink(socket_path);
	return 0;
}
