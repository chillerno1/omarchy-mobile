// SPDX-License-Identifier: MIT
// qseecom-probe: exercise the kernel's /dev/qseecom (the legacy QSEECOM
// interface to Qualcomm's QSEE) from plain Linux, before any vendor
// userspace exists. Built by tools/build-qseecom-probe; run as root.
//
//   qseecom-probe [--dev PATH] version
//       QSEECOM_IOCTL_GET_QSEOS_VERSION_REQ
//   qseecom-probe [--dev PATH] query NAME...
//       QSEECOM_IOCTL_APP_LOADED_QUERY_REQ for each NAME, one open of the
//       device per name. Loads nothing. The driver answers EEXIST (with
//       the app id) for a loaded app and 0 for one that is not. Careful: a
//       query of a loaded app takes a reference, and closing the device
//       drops it, so an app the bootloader loaded and nobody had
//       registered yet is unloaded when this program exits.
//   qseecom-probe [--dev PATH] load DIR NAME [--heap PATH] [--hold SECONDS]
//                 [--buffer BYTES]
//       Reads DIR/NAME.mdt and DIR/NAME.b00 .. NAME.bNN (one per ELF program
//       header, every one must exist), copies them back to back, .mdt first,
//       into one dma-buf from a dma-buf heap (default
//       /dev/dma_heap/default_cma_region), issues QSEECOM_IOCTL_LOAD_APP_REQ
//       with mdt_len = the .mdt's size, img_len = the total and app_arch =
//       the .mdt's ELF class, prints the app id, holds the app for SECONDS
//       (0: not at all), then QSEECOM_IOCTL_UNLOAD_APP_REQ. SIGINT or
//       SIGTERM ends the hold early and still unloads. --buffer makes the
//       dma-buf at least BYTES large (the image still starts at offset 0),
//       to see whether TrustZone minds the size of the buffer around it.
//   qseecom-probe [--dev PATH] listen ID[:SIZE][,ID[:SIZE]...]
//           [--heap PATH] [--reply fail|zero] [--seconds N]
//       Fake listener services. For each listener id (hex 0x.. or decimal):
//       fork a process that opens /dev/qseecom, allocates one dma-buf of SIZE
//       bytes from the heap (default /dev/dma_heap/default_cma_region;
//       rounded up to a page), mmaps it, registers the listener with
//       QSEECOM_IOCTL_REGISTER_LISTENER_REQ, then loops on
//       QSEECOM_IOCTL_RECEIVE_REQ. Each request is logged (timestamp, id,
//       hex dump of the first 64 bytes), a reply is written into the shared
//       buffer, and QSEECOM_IOCTL_SEND_RESP_REQ answers it. It opens no
//       storage/bsg/RPMB device and writes no file: a pure fake, to test
//       whether TrustZone will start a TA with the listener services present
//       but answering failure. --reply fail (default) writes the reply the
//       real listener sends on a failed operation for ids whose layout is
//       known (only RPMB 0x2000 here), and zeroes the buffer for the rest;
//       --reply zero always zeroes. SIGINT/SIGTERM, or --seconds N elapsing,
//       unregisters (QSEECOM_IOCTL_UNREGISTER_LISTENER_REQ) and exits.
//
// That layout is the one the vendor's QSEECom library builds (one buffer,
// whole files concatenated in that order, its length rounded up to 4 KiB,
// app_arch from e_ident[EI_CLASS], at most 99 segments), read from its
// disassembly; the vendor library allocates from the "qcom,qseecom-ta"
// heap. The driver needs the buffer physically contiguous: it hands the
// first scatterlist entry's address to QSEE.
//
// Every ioctl's result is printed with its errno. Exit status: 0 on
// success, 1 on any failure (for query: when a query itself failed).
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <linux/types.h>

// Mirrors include/uapi/linux/qseecom.h of the phone's kernel (GPL-2.0 WITH
// Linux-syscall-note): only what this program uses, under its own names.
#define QP_MAX_APP_NAME_SIZE 64
#define QP_IOC_MAGIC 0x97

struct qp_load_img_req {		// struct qseecom_load_img_req
	__u32 mdt_len;
	__u32 img_len;
	__s32 ifd_data_fd;
	char img_name[QP_MAX_APP_NAME_SIZE];
	__u32 app_arch;
	__u32 app_id;			// out
};

struct qp_qseos_version_req {		// struct qseecom_qseos_version_req
	unsigned int qseos_version;	// out
};

struct qp_app_load_query {		// struct qseecom_qseos_app_load_query
	char app_name[QP_MAX_APP_NAME_SIZE];
	__u32 app_id;			// out
	__u32 app_arch;			// out
};

struct qp_register_listener_req {	// struct qseecom_register_listener_req
	__u32 listener_id;		// in
	__s32 ifd_data_fd;		// in
	void *virt_sb_base;		// in
	__u32 sb_size;			// in
};

#define QP_IOCTL_REGISTER_LISTENER_REQ \
	_IOWR(QP_IOC_MAGIC, 1, struct qp_register_listener_req)
#define QP_IOCTL_UNREGISTER_LISTENER_REQ \
	_IO(QP_IOC_MAGIC, 2)
#define QP_IOCTL_RECEIVE_REQ \
	_IO(QP_IOC_MAGIC, 5)
#define QP_IOCTL_SEND_RESP_REQ \
	_IO(QP_IOC_MAGIC, 6)
#define QP_IOCTL_LOAD_APP_REQ \
	_IOWR(QP_IOC_MAGIC, 7, struct qp_load_img_req)
#define QP_IOCTL_UNLOAD_APP_REQ \
	_IO(QP_IOC_MAGIC, 9)
#define QP_IOCTL_GET_QSEOS_VERSION_REQ \
	_IOWR(QP_IOC_MAGIC, 10, struct qp_qseos_version_req)
#define QP_IOCTL_APP_LOADED_QUERY_REQ \
	_IOWR(QP_IOC_MAGIC, 15, struct qp_app_load_query)

// The numbers the reference header gives on arm64 (checked with it below
// when built with -DQSEECOM_REF_HEADER, see tools/build-qseecom-probe).
_Static_assert(sizeof(struct qp_load_img_req) == 84, "load_img_req size");
_Static_assert(offsetof(struct qp_load_img_req, app_arch) == 76, "app_arch");
_Static_assert(offsetof(struct qp_load_img_req, app_id) == 80, "app_id");
_Static_assert(sizeof(struct qp_qseos_version_req) == 4, "version_req size");
_Static_assert(sizeof(struct qp_app_load_query) == 72, "app_load_query size");
_Static_assert(sizeof(struct qp_register_listener_req) == 24, "register_listener_req size");
_Static_assert(offsetof(struct qp_register_listener_req, listener_id) == 0, "listener_id");
_Static_assert(offsetof(struct qp_register_listener_req, ifd_data_fd) == 4, "ifd_data_fd");
_Static_assert(offsetof(struct qp_register_listener_req, virt_sb_base) == 8, "virt_sb_base");
_Static_assert(offsetof(struct qp_register_listener_req, sb_size) == 16, "sb_size");
// These match the ioctl constants the vendor QSEEComAPI.so uses (checked in
// its disassembly): REGISTER 0xc0189701, RECEIVE 0x9705, SEND_RESP 0x9706.
_Static_assert(QP_IOCTL_REGISTER_LISTENER_REQ == 0xc0189701u, "REGISTER_LISTENER_REQ");
_Static_assert(QP_IOCTL_UNREGISTER_LISTENER_REQ == 0x9702u, "UNREGISTER_LISTENER_REQ");
_Static_assert(QP_IOCTL_RECEIVE_REQ == 0x9705u, "RECEIVE_REQ");
_Static_assert(QP_IOCTL_SEND_RESP_REQ == 0x9706u, "SEND_RESP_REQ");
_Static_assert(QP_IOCTL_LOAD_APP_REQ == 0xc0549707u, "LOAD_APP_REQ");
_Static_assert(QP_IOCTL_UNLOAD_APP_REQ == 0x9709u, "UNLOAD_APP_REQ");
_Static_assert(QP_IOCTL_GET_QSEOS_VERSION_REQ == 0xc004970au, "GET_QSEOS_VERSION_REQ");
_Static_assert(QP_IOCTL_APP_LOADED_QUERY_REQ == 0xc048970fu, "APP_LOADED_QUERY_REQ");

#ifdef QSEECOM_REF_HEADER
#include QSEECOM_REF_HEADER
#define QP_SAME(a, b) _Static_assert((a) == (b), #a " != " #b)
QP_SAME(QP_MAX_APP_NAME_SIZE, MAX_APP_NAME_SIZE);
QP_SAME(QP_IOC_MAGIC, QSEECOM_IOC_MAGIC);
QP_SAME(sizeof(struct qp_load_img_req), sizeof(struct qseecom_load_img_req));
QP_SAME(offsetof(struct qp_load_img_req, mdt_len), offsetof(struct qseecom_load_img_req, mdt_len));
QP_SAME(offsetof(struct qp_load_img_req, img_len), offsetof(struct qseecom_load_img_req, img_len));
QP_SAME(offsetof(struct qp_load_img_req, ifd_data_fd), offsetof(struct qseecom_load_img_req, ifd_data_fd));
QP_SAME(offsetof(struct qp_load_img_req, img_name), offsetof(struct qseecom_load_img_req, img_name));
QP_SAME(offsetof(struct qp_load_img_req, app_arch), offsetof(struct qseecom_load_img_req, app_arch));
QP_SAME(offsetof(struct qp_load_img_req, app_id), offsetof(struct qseecom_load_img_req, app_id));
QP_SAME(sizeof(struct qp_qseos_version_req), sizeof(struct qseecom_qseos_version_req));
QP_SAME(sizeof(struct qp_app_load_query), sizeof(struct qseecom_qseos_app_load_query));
QP_SAME(offsetof(struct qp_app_load_query, app_id), offsetof(struct qseecom_qseos_app_load_query, app_id));
QP_SAME(offsetof(struct qp_app_load_query, app_arch), offsetof(struct qseecom_qseos_app_load_query, app_arch));
QP_SAME(sizeof(struct qp_register_listener_req), sizeof(struct qseecom_register_listener_req));
QP_SAME(offsetof(struct qp_register_listener_req, listener_id), offsetof(struct qseecom_register_listener_req, listener_id));
QP_SAME(offsetof(struct qp_register_listener_req, ifd_data_fd), offsetof(struct qseecom_register_listener_req, ifd_data_fd));
QP_SAME(offsetof(struct qp_register_listener_req, virt_sb_base), offsetof(struct qseecom_register_listener_req, virt_sb_base));
QP_SAME(offsetof(struct qp_register_listener_req, sb_size), offsetof(struct qseecom_register_listener_req, sb_size));
QP_SAME(QP_IOCTL_REGISTER_LISTENER_REQ, QSEECOM_IOCTL_REGISTER_LISTENER_REQ);
QP_SAME(QP_IOCTL_UNREGISTER_LISTENER_REQ, QSEECOM_IOCTL_UNREGISTER_LISTENER_REQ);
QP_SAME(QP_IOCTL_RECEIVE_REQ, QSEECOM_IOCTL_RECEIVE_REQ);
QP_SAME(QP_IOCTL_SEND_RESP_REQ, QSEECOM_IOCTL_SEND_RESP_REQ);
QP_SAME(QP_IOCTL_LOAD_APP_REQ, QSEECOM_IOCTL_LOAD_APP_REQ);
QP_SAME(QP_IOCTL_UNLOAD_APP_REQ, QSEECOM_IOCTL_UNLOAD_APP_REQ);
QP_SAME(QP_IOCTL_GET_QSEOS_VERSION_REQ, QSEECOM_IOCTL_GET_QSEOS_VERSION_REQ);
QP_SAME(QP_IOCTL_APP_LOADED_QUERY_REQ, QSEECOM_IOCTL_APP_LOADED_QUERY_REQ);
#endif

#define MAX_SEGMENTS 99		// the vendor library refuses e_phnum >= 100

static const char *dev_path = "/dev/qseecom";
static volatile sig_atomic_t stop_signal;

static void on_signal(int sig)
{
	stop_signal = sig;
}

static void usage(FILE *f)
{
	fprintf(f,
		"usage: qseecom-probe [--dev PATH] version\n"
		"       qseecom-probe [--dev PATH] query NAME...\n"
		"       qseecom-probe [--dev PATH] load DIR NAME [--heap PATH] [--hold SECONDS] [--buffer BYTES]\n"
		"       qseecom-probe [--dev PATH] listen ID[:SIZE][,ID[:SIZE]...] [--heap PATH]\n"
		"                     [--reply fail|zero] [--seconds N]\n");
}

static const char *errname(int e)
{
	switch (e) {
	case 0: return "OK";
	case EPERM: return "EPERM";
	case ENOENT: return "ENOENT";
	case EINTR: return "EINTR";
	case EIO: return "EIO";
	case ENXIO: return "ENXIO";
	case EBADF: return "EBADF";
	case EAGAIN: return "EAGAIN";
	case ENOMEM: return "ENOMEM";
	case EACCES: return "EACCES";
	case EFAULT: return "EFAULT";
	case EBUSY: return "EBUSY";
	case EEXIST: return "EEXIST";
	case ENODEV: return "ENODEV";
	case EINVAL: return "EINVAL";
	case ENOTTY: return "ENOTTY";
	case ENOSPC: return "ENOSPC";
	case ENOSYS: return "ENOSYS";
	case EOPNOTSUPP: return "EOPNOTSUPP";
	case ETIMEDOUT: return "ETIMEDOUT";
	default: return "E?";
	}
}

// Print one syscall's outcome: "ioctl LOAD_APP_REQ: -1 errno 22 EINVAL (...)".
static void report(const char *what, long ret, int err)
{
	if (ret < 0)
		fprintf(stderr, "%s: %ld errno %d %s (%s)\n", what, ret, err,
			errname(err), strerror(err));
	else
		printf("%s: %ld\n", what, ret);
}

static void report_path(const char *op, const char *path, int err)
{
	fprintf(stderr, "%s %s: -1 errno %d %s (%s)\n", op, path, err,
		errname(err), strerror(err));
}

static int open_dev(void)
{
	int fd = open(dev_path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		report_path("open", dev_path, errno);
	}
	return fd;
}

static int cmd_version(void)
{
	int fd = open_dev();
	if (fd < 0)
		return 1;
	struct qp_qseos_version_req req = {0};
	int ret = ioctl(fd, QP_IOCTL_GET_QSEOS_VERSION_REQ, &req);
	int e = errno;
	report("ioctl GET_QSEOS_VERSION_REQ", ret, e);
	close(fd);
	if (ret < 0)
		return 1;
	printf("qseos_version %u (0x%x)\n", req.qseos_version, req.qseos_version);
	return 0;
}

static int cmd_query(int n, char **names)
{
	int failed = 0;
	for (int i = 0; i < n; i++) {
		if (strlen(names[i]) >= QP_MAX_APP_NAME_SIZE) {
			fprintf(stderr, "%s: name longer than %d bytes\n", names[i],
				QP_MAX_APP_NAME_SIZE - 1);
			failed = 1;
			continue;
		}
		// A fresh open per name: the driver binds the queried app to
		// the handle, and a second query on it would leak a reference.
		int fd = open_dev();
		if (fd < 0)
			return 1;
		struct qp_app_load_query q = {0};
		strcpy(q.app_name, names[i]);
		int ret = ioctl(fd, QP_IOCTL_APP_LOADED_QUERY_REQ, &q);
		int e = errno;
		char what[QP_MAX_APP_NAME_SIZE + 48];
		snprintf(what, sizeof(what), "ioctl APP_LOADED_QUERY_REQ %s", names[i]);
		if (ret == 0) {
			report(what, ret, 0);
			printf("%s: not loaded\n", names[i]);
		} else if (e == EEXIST) {
			printf("%s: -1 errno %d EEXIST (loaded)\n", what, e);
			printf("%s: loaded, app id %u, app_arch %u\n", names[i],
			       q.app_id, q.app_arch);
		} else {
			report(what, ret, e);
			printf("%s: query failed\n", names[i]);
			failed = 1;
		}
		close(fd);
	}
	return failed;
}

struct segment {
	char path[PATH_MAX];
	off_t size;
};

// Read the ELF header of NAME.mdt: class (1 or 2) and e_phnum.
static int read_mdt_header(const char *path, unsigned *cls, unsigned *phnum)
{
	unsigned char h[64];
	FILE *f = fopen(path, "rb");
	if (!f) {
		report_path("open", path, errno);
		return -1;
	}
	size_t got = fread(h, 1, sizeof(h), f);
	fclose(f);
	if (got < 52 || memcmp(h, "\177ELF", 4) != 0) {
		fprintf(stderr, "%s: not an ELF file\n", path);
		return -1;
	}
	*cls = h[4];
	// e_phnum, little-endian: offset 44 (ELF32) or 56 (ELF64)
	if (*cls == 1)
		*phnum = h[44] | h[45] << 8;
	else if (*cls == 2 && got == 64)
		*phnum = h[56] | h[57] << 8;
	else {
		fprintf(stderr, "%s: unknown ELF class %u\n", path, *cls);
		return -1;
	}
	if (*phnum == 0xffff || *phnum > MAX_SEGMENTS) {
		fprintf(stderr, "%s: %u program headers, at most %d supported\n",
			path, *phnum, MAX_SEGMENTS);
		return -1;
	}
	return 0;
}

static int copy_file(const char *path, unsigned char *dst, off_t size)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		report_path("open", path, errno);
		return -1;
	}
	off_t done = 0;
	while (done < size) {
		ssize_t r = read(fd, dst + done, size - done);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0) {
			report_path("read", path, r < 0 ? errno : EIO);
			close(fd);
			return -1;
		}
		done += r;
	}
	close(fd);
	return 0;
}

static int dmabuf_sync(int fd, __u64 flags, const char *what)
{
	struct dma_buf_sync s = { .flags = flags };
	int ret = ioctl(fd, DMA_BUF_IOCTL_SYNC, &s);
	if (ret < 0)
		report(what, ret, errno);
	return ret;
}

static int cmd_load(const char *dir, const char *name, const char *heap, long hold,
		    uint64_t minbuf)
{
	if (strlen(name) >= QP_MAX_APP_NAME_SIZE) {
		fprintf(stderr, "%s: name longer than %d bytes\n", name,
			QP_MAX_APP_NAME_SIZE - 1);
		return 1;
	}

	// 1. The files: NAME.mdt, then NAME.b00 .. NAME.b(e_phnum - 1).
	static struct segment seg[MAX_SEGMENTS + 1];
	unsigned cls, phnum;
	snprintf(seg[0].path, sizeof(seg[0].path), "%s/%s.mdt", dir, name);
	if (read_mdt_header(seg[0].path, &cls, &phnum) < 0)
		return 1;
	for (unsigned i = 1; i <= phnum; i++)
		snprintf(seg[i].path, sizeof(seg[i].path), "%s/%s.b%02u", dir,
			 name, i - 1);
	uint64_t total = 0;
	for (unsigned i = 0; i <= phnum; i++) {
		struct stat st;
		if (stat(seg[i].path, &st) < 0) {
			report_path("stat", seg[i].path, errno);
			return 1;
		}
		seg[i].size = st.st_size;
		total += (uint64_t)st.st_size;
	}
	if (total > UINT32_MAX - 4095) {
		fprintf(stderr, "image too large: %llu bytes\n", (unsigned long long)total);
		return 1;
	}
	uint64_t buflen = (total + 4095) & ~(uint64_t)4095;
	if (minbuf > buflen)
		buflen = (minbuf + 4095) & ~(uint64_t)4095;
	printf("image %s/%s: ELF class %u (%s), %u segments\n", dir, name, cls,
	       cls == 2 ? "64-bit" : "32-bit", phnum);
	uint64_t off = 0;
	for (unsigned i = 0; i <= phnum; i++) {
		printf("  0x%08llx %10lld %s\n", (unsigned long long)off,
		       (long long)seg[i].size, seg[i].path);
		off += seg[i].size;
	}
	printf("mdt_len %lld, img_len %llu, buffer %llu bytes\n",
	       (long long)seg[0].size, (unsigned long long)total,
	       (unsigned long long)buflen);

	struct sigaction sa = { .sa_handler = on_signal };	// no SA_RESTART
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	// 2. The device first, as the vendor library does.
	int qfd = open_dev();
	if (qfd < 0)
		return 1;

	// 3. One dma-buf for the whole image.
	int rc = 1, bfd = -1;
	unsigned char *map = MAP_FAILED;
	int hfd = open(heap, O_RDONLY | O_CLOEXEC);
	if (hfd < 0) {
		report_path("open", heap, errno);
		goto out;
	}
	struct dma_heap_allocation_data alloc = {
		.len = buflen,
		.fd_flags = O_RDWR | O_CLOEXEC,
	};
	int ret = ioctl(hfd, DMA_HEAP_IOCTL_ALLOC, &alloc);
	int e = errno;
	close(hfd);
	report("ioctl DMA_HEAP_IOCTL_ALLOC", ret, e);
	if (ret < 0)
		goto out;
	bfd = alloc.fd;
	map = mmap(NULL, buflen, PROT_READ | PROT_WRITE, MAP_SHARED, bfd, 0);
	if (map == MAP_FAILED) {
		report("mmap dma-buf", -1, errno);
		goto out;
	}
	if (dmabuf_sync(bfd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_RW,
			"ioctl DMA_BUF_IOCTL_SYNC start") < 0)
		goto out;
	memset(map, 0, buflen);
	off = 0;
	for (unsigned i = 0; i <= phnum; i++) {
		if (copy_file(seg[i].path, map + off, seg[i].size) < 0)
			goto out;
		off += seg[i].size;
	}
	if (dmabuf_sync(bfd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_RW,
			"ioctl DMA_BUF_IOCTL_SYNC end") < 0)
		goto out;
	munmap(map, buflen);
	map = MAP_FAILED;

	// 4. Load.
	struct qp_load_img_req req = {
		.mdt_len = (__u32)seg[0].size,
		.img_len = (__u32)total,
		.ifd_data_fd = bfd,
		.app_arch = cls,
	};
	strcpy(req.img_name, name);
	ret = ioctl(qfd, QP_IOCTL_LOAD_APP_REQ, &req);
	e = errno;
	report("ioctl LOAD_APP_REQ", ret, e);
	// The driver has copied what it needs; the buffer can go.
	close(bfd);
	bfd = -1;
	if (ret < 0)
		goto out;
	printf("%s: loaded, app id %u\n", name, req.app_id);
	rc = 0;

	// 5. Hold, then unload.
	if (hold > 0 && !stop_signal) {
		printf("holding %s for %ld s (SIGINT or SIGTERM to stop)\n", name, hold);
		fflush(stdout);
		struct timespec left = { .tv_sec = hold };
		while (!stop_signal && nanosleep(&left, &left) < 0 && errno == EINTR)
			;
	}
	if (stop_signal)
		printf("signal %d: unloading\n", (int)stop_signal);
	ret = ioctl(qfd, QP_IOCTL_UNLOAD_APP_REQ);
	e = errno;
	report("ioctl UNLOAD_APP_REQ", ret, e);
	if (ret < 0)
		rc = 1;
	else
		printf("%s: unloaded\n", name);
out:
	if (map != MAP_FAILED)
		munmap(map, buflen);
	if (bfd >= 0)
		close(bfd);
	close(qfd);
	return rc;
}

// ---- listener services (the `listen` subcommand) --------------------------
//
// Default shared-buffer size per known listener id, and the reply layout.
//
// What the real qseecomd listeners do, from the vendor libraries' aarch64
// disassembly (llvm-objdump; reference binaries under vendor/, never built or
// shipped). A listener's `*_start` entry allocates one dma-buf of a fixed
// size from a dma-buf heap and calls QSEECom_register_listener(handle, id,
// sb, size, 0); registration order is: open /dev/qseecom, GET_QSEOS_VERSION,
// allocate+mmap the dma-buf, then REGISTER_LISTENER. No SET_MEM_PARAM_REQ and
// no other ioctl precedes it. A pthread then loops on QSEECom_receive_req()
// and QSEECom_send_resp(), reading the request and writing the reply in the
// *same* shared buffer. The sizes registered (high confidence, read straight
// from the `mov w2, #imm` before each register call):
//   0x2000 librpmb  rpmb_start   0x6400 (25600)
//   0x3000 libssd   ssd_start    0x5000 (20480)
//   0xb    libdrmtime atime_start 0x5000 (20480)
//   0xa    libdrmfs fs_start     0x5000 (20480)
// gpfs_start (0x7000) registers through a helper whose size I did not pin
// down; the other ids here (0x9000 qisl, 0x1100 GPreqcancel, 0xc000 ops,
// 0xb000 spl) were not disassembled. They fall back to a generic 0x5000,
// which is the size every listener I did read uses except RPMB.
//
// Reply layout. RPMB (0x2000) is the one the anti-rollback (app version)
// check needs, so it is the one established in full. Its listener thread
// (librpmb.so rpmb_start, .text+0x1334) reads the request in place:
//   req+0x0  u32 command id (0x101 init, 0x102 read, 0x103 write, 0x104 cfg)
// and writes the response in the same buffer. On a *failed* read/write it
// does (librpmb .text+0x75cc): keep command id at +0, store the operation's
// negative result at +4 (0xffffffff / -1 for a failed device op), store 0x14
// (the 20-byte response length) at +0xc, and QSEECom_send_resp with len 20:
//   resp+0x0  u32 command id   (echoed, unchanged)
//   resp+0x4  u32 status       (0 = success; 0xffffffff = failed op;
//                               0xfffffff9 = unknown command)
//   resp+0x8  u32 (0)
//   resp+0xc  u32 0x14         (response length)
// So `--reply fail` for RPMB answers "operation failed": command id echoed,
// status 0xffffffff, length word 0x14. Confidence: high for RPMB.
//
// SSD (0x3000) and time (0xb) were traced far enough to see the command id at
// req+0 and a status word written near the start of the reply, but not far
// enough to be sure of the failing status value, so they are NOT crafted:
// under `--reply fail` their buffer is zeroed (the output says so), which
// still delivers a well-formed, if content-free, response. `--reply zero`
// always zeroes.
//
// Note on the shared buffer: the vendor QSEECom_receive_req, when the QSEOS
// version is 0x14, copies the shared buffer into a caller buffer and then
// *zeroes* the shared buffer; the vendor listeners that pass the shared
// buffer as their own caller buffer rely on the device reporting a version
// other than 0x14 so that path is skipped. We do not use that library: our
// RECEIVE_REQ leaves the shared buffer untouched (see the kernel note in the
// report), so this probe reads the request and writes the reply directly in
// the mmap, bracketed by DMA_BUF_IOCTL_SYNC as the load path does.

#define QP_LISTEN_DEFAULT_SIZE 0x5000u	// generic default (what ssd/fs/time use)
#define QP_RPMB_LISTENER_ID    0x2000u

struct qp_known_listener {
	__u32 id;
	__u32 size;
};

static const struct qp_known_listener qp_known_listeners[] = {
	{ 0x2000, 0x6400 },	// RPMB  (librpmb  rpmb_start)
	{ 0x3000, 0x5000 },	// SSD   (libssd   ssd_start)
	{ 0x000b, 0x5000 },	// time  (libdrmtime atime_start)
	{ 0x000a, 0x5000 },	// fs    (libdrmfs fs_start)
	{ 0x7000, 0x5000 },	// gpfs  (libdrmfs gpfs_start; size assumed)
};

static __u32 qp_default_size(__u32 id)
{
	for (size_t i = 0; i < sizeof(qp_known_listeners) / sizeof(qp_known_listeners[0]); i++)
		if (qp_known_listeners[i].id == id)
			return qp_known_listeners[i].size;
	return QP_LISTEN_DEFAULT_SIZE;
}

enum qp_reply_mode { QP_REPLY_FAIL, QP_REPLY_ZERO };

static void qp_timestamp(char *buf, size_t n)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	struct tm tm;
	localtime_r(&ts.tv_sec, &tm);
	char hms[16];
	strftime(hms, sizeof(hms), "%H:%M:%S", &tm);
	snprintf(buf, n, "%s.%03ld", hms, ts.tv_nsec / 1000000);
}

static void qp_hexdump64(const unsigned char *p, __u32 sb_size)
{
	__u32 n = sb_size < 64 ? sb_size : 64;
	for (__u32 i = 0; i < n; i += 16) {
		printf("    %04x  ", i);
		for (__u32 j = 0; j < 16 && i + j < n; j++)
			printf("%02x%s", p[i + j], j == 7 ? "  " : " ");
		printf("\n");
	}
}

// Fill the reply in the shared buffer; return the response length to report.
// *crafted is set when a real layout was reproduced (vs. a bare zeroed buffer).
static __u32 qp_build_reply(__u32 id, enum qp_reply_mode mode, unsigned char *sb,
			    __u32 sb_size, int *crafted)
{
	*crafted = 0;
	if (mode == QP_REPLY_FAIL && id == QP_RPMB_LISTENER_ID && sb_size >= 16) {
		// Echo the command id the TA sent, report a failed operation.
		__u32 cmd_id;
		memcpy(&cmd_id, sb, 4);
		memset(sb, 0, sb_size);
		memcpy(sb + 0x0, &cmd_id, 4);		// command id, echoed
		__u32 status = 0xffffffffu;		// failed device op
		__u32 length = 0x14;			// 20-byte response
		memcpy(sb + 0x4, &status, 4);
		memcpy(sb + 0xc, &length, 4);
		*crafted = 1;
		return 0x14;
	}
	// Unknown layout, or --reply zero: a well-formed but content-free reply.
	memset(sb, 0, sb_size);
	return sb_size;
}

// Run one listener in the current process; returns 0 on a clean exit.
static int qp_run_listener(__u32 id, __u32 size, const char *heap,
			   enum qp_reply_mode mode, long seconds)
{
	struct sigaction sa = { .sa_handler = on_signal };	// no SA_RESTART
	sigemptyset(&sa.sa_mask);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGALRM, &sa, NULL);

	__u32 buflen = (size + 4095u) & ~4095u;			// page-rounded alloc

	int rc = 1, bfd = -1, hfd = -1;
	unsigned char *map = MAP_FAILED;

	int qfd = open_dev();
	if (qfd < 0)
		return 1;

	// Mirror the vendor order: GET_QSEOS_VERSION before registering.
	struct qp_qseos_version_req ver = {0};
	int ret = ioctl(qfd, QP_IOCTL_GET_QSEOS_VERSION_REQ, &ver);
	int e = errno;
	report("ioctl GET_QSEOS_VERSION_REQ", ret, e);
	if (ret == 0)
		printf("listener 0x%x: qseos_version 0x%x\n", id, ver.qseos_version);

	hfd = open(heap, O_RDONLY | O_CLOEXEC);
	if (hfd < 0) {
		report_path("open", heap, errno);
		goto out;
	}
	struct dma_heap_allocation_data alloc = {
		.len = buflen,
		.fd_flags = O_RDWR | O_CLOEXEC,
	};
	ret = ioctl(hfd, DMA_HEAP_IOCTL_ALLOC, &alloc);
	e = errno;
	close(hfd);
	hfd = -1;
	report("ioctl DMA_HEAP_IOCTL_ALLOC", ret, e);
	if (ret < 0)
		goto out;
	bfd = alloc.fd;
	map = mmap(NULL, buflen, PROT_READ | PROT_WRITE, MAP_SHARED, bfd, 0);
	if (map == MAP_FAILED) {
		report("mmap dma-buf", -1, errno);
		goto out;
	}
	memset(map, 0, buflen);

	struct qp_register_listener_req req = {
		.listener_id = id,
		.ifd_data_fd = bfd,
		.virt_sb_base = map,
		.sb_size = size,		// requested size, not the rounded alloc
	};
	ret = ioctl(qfd, QP_IOCTL_REGISTER_LISTENER_REQ, &req);
	e = errno;
	report("ioctl REGISTER_LISTENER_REQ", ret, e);
	if (ret < 0)
		goto out;
	printf("listener 0x%x: registered, shared buffer %u bytes (alloc %u), reply %s\n",
	       id, size, buflen, mode == QP_REPLY_ZERO ? "zero" : "fail");

	if (seconds > 0)
		alarm((unsigned)seconds);

	// The receive loop: block until TrustZone has a request for this id.
	unsigned long count = 0;
	while (!stop_signal) {
		ret = ioctl(qfd, QP_IOCTL_RECEIVE_REQ);
		e = errno;
		if (ret < 0) {
			if (e == EINTR)
				break;		// signal or alarm: time to stop
			report("ioctl RECEIVE_REQ", ret, e);
			break;
		}
		if (stop_signal)
			break;
		dmabuf_sync(bfd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_RW,
			    "ioctl DMA_BUF_IOCTL_SYNC start");
		char ts[32];
		qp_timestamp(ts, sizeof(ts));
		__u32 cmd_id;
		memcpy(&cmd_id, map, 4);
		printf("%s listener 0x%x req #%lu: command id 0x%x\n",
		       ts, id, ++count, cmd_id);
		qp_hexdump64(map, size);
		int crafted;
		__u32 resp_len = qp_build_reply(id, mode, map, size, &crafted);
		printf("%s listener 0x%x reply: %s, %u bytes\n", ts, id,
		       crafted ? "crafted failure (layout known)" :
		       (mode == QP_REPLY_ZERO ? "zeroed (--reply zero)" :
			"zeroed (layout not established)"),
		       resp_len);
		dmabuf_sync(bfd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_RW,
			    "ioctl DMA_BUF_IOCTL_SYNC end");
		ret = ioctl(qfd, QP_IOCTL_SEND_RESP_REQ);
		e = errno;
		report("ioctl SEND_RESP_REQ", ret, e);
		if (ret < 0)
			break;
	}
	if (stop_signal)
		printf("listener 0x%x: signal %d, unregistering\n", id, (int)stop_signal);
	rc = 0;

	ret = ioctl(qfd, QP_IOCTL_UNREGISTER_LISTENER_REQ);
	e = errno;
	report("ioctl UNREGISTER_LISTENER_REQ", ret, e);
	if (ret < 0)
		rc = 1;
	else
		printf("listener 0x%x: unregistered\n", id);
out:
	if (map != MAP_FAILED)
		munmap(map, buflen);
	if (bfd >= 0)
		close(bfd);
	if (hfd >= 0)
		close(hfd);
	close(qfd);
	return rc;
}

#define QP_MAX_LISTENERS 32

static int cmd_listen(const char *spec, const char *heap, enum qp_reply_mode mode,
		      long seconds)
{
	// Parse ID[:SIZE][,ID[:SIZE]...].
	__u32 ids[QP_MAX_LISTENERS], sizes[QP_MAX_LISTENERS];
	int n = 0;
	char *dup = strdup(spec);
	if (!dup) {
		fprintf(stderr, "out of memory\n");
		return 2;
	}
	for (char *tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
		if (n >= QP_MAX_LISTENERS) {
			fprintf(stderr, "too many listeners (max %d)\n", QP_MAX_LISTENERS);
			free(dup);
			return 2;
		}
		char *colon = strchr(tok, ':');
		if (colon)
			*colon = '\0';
		char *end;
		unsigned long id = strtoul(tok, &end, 0);
		if (*end || tok[0] == '\0' || id == 0 || id > 0xffffffffUL) {
			fprintf(stderr, "listen: bad listener id: %s\n", tok);
			free(dup);
			return 2;
		}
		__u32 size;
		if (colon) {
			unsigned long s = strtoul(colon + 1, &end, 0);
			if (*end || colon[1] == '\0' || s == 0 || s > 0x10000000UL) {
				fprintf(stderr, "listen: bad size: %s\n", colon + 1);
				free(dup);
				return 2;
			}
			size = (__u32)s;
		} else {
			size = qp_default_size((__u32)id);
		}
		ids[n] = (__u32)id;
		sizes[n] = size;
		n++;
	}
	free(dup);
	if (n == 0) {
		fprintf(stderr, "listen: no listener ids given\n");
		return 2;
	}

	if (n == 1)
		return qp_run_listener(ids[0], sizes[0], heap, mode, seconds);

	// One child process per listener; each has its own /dev/qseecom handle
	// (the listener id is bound to the fd). Ctrl-C reaches the whole process
	// group; --seconds is enforced by each child's own alarm.
	pid_t pids[QP_MAX_LISTENERS];
	int started = 0;
	for (int i = 0; i < n; i++) {
		pid_t pid = fork();
		if (pid < 0) {
			report("fork", -1, errno);
			break;
		}
		if (pid == 0) {
			_exit(qp_run_listener(ids[i], sizes[i], heap, mode, seconds));
		}
		pids[i] = pid;
		started++;
	}
	int rc = 0;
	for (int i = 0; i < started; i++) {
		int status;
		if (waitpid(pids[i], &status, 0) < 0) {
			report("waitpid", -1, errno);
			rc = 1;
		} else if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			rc = 1;
		}
	}
	return rc;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	int i = 1;
	if (i + 1 < argc && strcmp(argv[i], "--dev") == 0) {
		dev_path = argv[i + 1];
		i += 2;
	}
	if (i >= argc) {
		usage(stderr);
		return 2;
	}
	const char *cmd = argv[i++];
	if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
		usage(stdout);
		return 0;
	}
	if (strcmp(cmd, "version") == 0 && i == argc)
		return cmd_version();
	if (strcmp(cmd, "query") == 0 && i < argc)
		return cmd_query(argc - i, argv + i);
	if (strcmp(cmd, "load") == 0 && i + 2 <= argc) {
		const char *dir = argv[i], *name = argv[i + 1];
		const char *heap = "/dev/dma_heap/default_cma_region";
		long hold = 0;
		uint64_t minbuf = 0;
		for (i += 2; i < argc; i += 2) {
			if (i + 1 >= argc)
				break;
			if (strcmp(argv[i], "--heap") == 0) {
				heap = argv[i + 1];
			} else if (strcmp(argv[i], "--hold") == 0) {
				char *end;
				hold = strtol(argv[i + 1], &end, 10);
				if (*end || hold < 0) {
					fprintf(stderr, "--hold: not a number of seconds: %s\n",
						argv[i + 1]);
					return 2;
				}
			} else if (strcmp(argv[i], "--buffer") == 0) {
				char *end;
				minbuf = strtoull(argv[i + 1], &end, 0);
				if (*end || !minbuf || minbuf > (1ull << 30)) {
					fprintf(stderr, "--buffer: not a size in bytes (up to 1 GiB): %s\n",
						argv[i + 1]);
					return 2;
				}
			} else {
				break;
			}
		}
		if (i == argc)
			return cmd_load(dir, name, heap, hold, minbuf);
	}
	if (strcmp(cmd, "listen") == 0 && i < argc) {
		const char *spec = argv[i];
		const char *heap = "/dev/dma_heap/default_cma_region";
		enum qp_reply_mode mode = QP_REPLY_FAIL;
		long seconds = 0;
		for (i += 1; i < argc; i += 2) {
			if (i + 1 >= argc)
				break;
			if (strcmp(argv[i], "--heap") == 0) {
				heap = argv[i + 1];
			} else if (strcmp(argv[i], "--reply") == 0) {
				if (strcmp(argv[i + 1], "fail") == 0)
					mode = QP_REPLY_FAIL;
				else if (strcmp(argv[i + 1], "zero") == 0)
					mode = QP_REPLY_ZERO;
				else {
					fprintf(stderr, "--reply: fail or zero, not: %s\n",
						argv[i + 1]);
					return 2;
				}
			} else if (strcmp(argv[i], "--seconds") == 0) {
				char *end;
				seconds = strtol(argv[i + 1], &end, 10);
				if (*end || seconds < 0) {
					fprintf(stderr, "--seconds: not a count: %s\n",
						argv[i + 1]);
					return 2;
				}
			} else {
				break;
			}
		}
		if (i == argc)
			return cmd_listen(spec, heap, mode, seconds);
	}
	usage(stderr);
	return 2;
}
