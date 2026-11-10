# SPDX-License-Identifier: MIT
# Builds the Solana Saga's (ingot) fingerprint chroot programs, bionic
# aarch64, on the computer:
#
#   out/librpmb.so             RPMB listener stub, replaces the vendor's
#   out/libssd.so              SSD listener stub, replaces the vendor's
#   out/omamobile-fp-halhost   loads and drives the fingerprint HAL module
#   out/omamobile-fp-shim.so   the preload shim (../shim), for this chroot
#
#   make NDK=/opt/android-ndk CHROOT=...   (Android NDK r27 or later)
#
# CHROOT is tools/extract-fingerprint-vendor-ingot's output root: everything
# links against its libc, libdl and liblog, the stubs against its
# libQSEEComAPI.so, so they match the phone exactly.
#
# In the chroot (as root; qseecomd drops to uid/gid 1000 itself), with the
# stubs' directory first, e.g. /omamobile/lib64:
#   LD_LIBRARY_PATH=/omamobile/lib64:/vendor/lib64:/system/lib64
#   LD_PRELOAD=/omamobile/lib64/omamobile-fp-shim.so   (liblog to stderr,
#                                                      properties as files)
# qseecomd waits up to 60 s for /dev/qseecom, then serves; the HAL host
# needs /dev/blfp and /dev/qseecom (and the dma-buf heaps
# /dev/dma_heap/qcom,qseecom and qcom,qseecom-ta) once qseecomd runs.

API      ?= 35
OUT      ?= out
CFLAGS   ?= -O2
WARN     := -Wall -Wextra -Werror
STUB_SRC := stubs/omamobile-listener-stub.c
HALHOST_SRC := halhost/omamobile-fp-halhost.c
SHIM_SRC := ../shim/omamobile-fp-shim.c

ifndef CHROOT
$(error set CHROOT=<extract-fingerprint-vendor-ingot output>/root)
endif
ifndef NDK
$(error set NDK=<android-ndk r27 or later>)
endif
CC       := $(NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android$(API)-clang

LIBC     := $(CHROOT)/apex/com.android.runtime/lib64/bionic/libc.so
LIBDL    := $(CHROOT)/apex/com.android.runtime/lib64/bionic/libdl.so
LIBLOG   := $(CHROOT)/system/lib64/liblog.so
LIBQSEECOM := $(CHROOT)/vendor/lib64/libQSEEComAPI.so

all: $(OUT)/librpmb.so $(OUT)/libssd.so $(OUT)/omamobile-fp-halhost \
	$(OUT)/omamobile-fp-shim.so

# Only the entry points qseecomd resolves are exported.
STUB_LINK = $(CC) $(CFLAGS) $(WARN) -fPIC -fvisibility=hidden -shared \
	-nostdlib -Wl,--no-undefined -Wl,-z,now -Wl,-z,relro

$(OUT)/librpmb.so: $(STUB_SRC)
	@mkdir -p $(OUT)
	$(STUB_LINK) -DSTUB_RPMB -Wl,-soname,librpmb.so -o $@ $< \
		$(LIBQSEECOM) $(LIBLOG) $(LIBC)

$(OUT)/libssd.so: $(STUB_SRC)
	@mkdir -p $(OUT)
	$(STUB_LINK) -DSTUB_SSD -Wl,-soname,libssd.so -o $@ $< \
		$(LIBQSEECOM) $(LIBLOG) $(LIBC)

# No crtbegin: the host has its own _start (see its header).
$(OUT)/omamobile-fp-halhost: $(HALHOST_SRC)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(WARN) -fPIE -pie -nostdlib -fno-stack-protector \
		-Wl,--dynamic-linker=/system/bin/linker64 -Wl,-z,now \
		-Wl,-z,relro -Wl,--hash-style=gnu -Wl,--no-undefined \
		-o $@ $< $(LIBDL) $(LIBC)

$(OUT)/omamobile-fp-shim.so: $(SHIM_SRC)
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $(WARN) -fPIC -fvisibility=hidden -shared -nostdlib \
		-Wl,--no-undefined -Wl,-soname,omamobile-fp-shim.so -o $@ $< \
		$(LIBC) $(LIBDL)

clean:
	rm -rf $(OUT)

.PHONY: all clean
