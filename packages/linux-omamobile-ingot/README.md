<!-- SPDX-License-Identifier: MIT -->
# linux-omamobile-ingot

The Solana Mobile Saga's (`ingot`, SM8475) bring-up kernel, packed for one
developer's phone: its modules and the slot-A boot images built from it,
which `omamobile-ingot-boot` writes. Nothing compiles here; `./stage`
copies a finished kernel build and a finished image set into the
gitignored `prebuilt/`, and the PKGBUILD packs them.

**This package is never published.** `boot_a.img`'s initramfs carries the
developer's SSH public key, and the kernel is a local development build
(releases like `7.3.0-rc6-omamobile-push1-g837bf17d318a`), not a release
tag. So:

- `tools/build-packages` builds it only when named (`NAMED_ONLY`, never by
  default or with `--all`), and only with `--local <codename>`, into that
  contributor's own repository (`out/<codename>/repo`), never `out/repo`;
  it also refuses to `--import` it into `out/repo`.
- `tools/repo-publish` refuses any index that lists it, before uploading,
  and `--from-main` does not copy this package's `prebuilt/` into its clean
  tree.

It is separate from `linux-omamobile` (one kernel for every device, from a
published release tag only), whose refusals stay as they are.

**Not yet run on a phone.** Tested offline (`test/all`: a fake kernel build
and image set, the refusals, the layout, `makepkg -A` where installed).

## Staging (laptop)

```sh
# the kernel and its modules
KERNEL_DIR=~/omamobile-kernel/<tree> KERNEL_OUT=~/omamobile-kernel/out-ingot bin/omamobile kernel
KERNEL_OUT=~/omamobile-kernel/out-ingot bin/omamobile modules
# the boot images from that kernel (boot_a.img, vendor_boot.img, dtbo.img, RELEASE, SHA256SUMS)
tools/build-ingot-probe --standalone --kernel ~/omamobile-kernel/out-ingot/arch/arm64/boot/Image.gz ... --out IMAGES
# into prebuilt/
KERNEL_DIR=~/omamobile-kernel/<tree> packages/linux-omamobile-ingot/stage ~/omamobile-kernel/out-ingot IMAGES
```

`stage KERNEL_OUT IMAGES_DIR [PREBUILT]` copies `kernel.release`, the
modules tarball `modules-<release>.tar.zst`, the board DTB
(`arch/arm64/boot/dts/qcom/sm8475-osom-ingot.dtb`) and the image set, with
`SHA256SUMS` and `SOURCE` (the commit and count). It refuses:

- a `-dirty` release (development releases are accepted: that is the point);
- a missing modules tarball (make it with `bin/omamobile modules`), one of
  another release, or one without `modules.order`;
- no board DTB;
- an image set that fails its `SHA256SUMS` or the structure the phone
  checks (`../omamobile-ingot-boot/lib/ingot-images.sh`: `boot_a.img` header
  v4, exactly 0x6000000 bytes, an AVB footer at its end; `vendor_boot.img`
  and `dtbo.img` magic and sizes);
- a `RELEASE` that is not the kernel's;
- a `boot_a.img` whose kernel (header v4: kernel size at offset 8, the
  kernel from offset 4096) is not `KERNEL_OUT/arch/arm64/boot/Image.gz`, so
  the packaged modules always belong to the kernel that boots;
- a `KERNEL_DIR` at another commit than the release names.

`stage --verify [PREBUILT]` checks a staged `prebuilt/` again;
`tools/build-packages` runs it before packing.

**pkgver** (`lib/pkgver`): the release without its `-`, then the commit
count and the commit, `7.3.0rc6.r<n>.g<sha>`. The count is
`git rev-list --count HEAD` of `KERNEL_DIR` when given, else the release's
own `-<n>-` count; with neither, `stage` refuses. Keep to one source (give
`KERNEL_DIR` every time): the two counts differ by the whole upstream
history. **pkgrel** is the `version` file (packaging changes only). With
nothing staged pkgver is `0` and `package()` refuses.

## Contents

- `/usr/lib/modules/<release>/`: the stripped modules as the tarball has
  them, and `pkgbase` (`linux-omamobile-ingot`). depmod's files are left to
  kmod's `60-depmod.hook`, as `linux-omamobile` does. No `vmlinuz` and no
  `dtbs/`: the kernel is inside `boot_a.img`.
- `/usr/lib/omamobile/ingot/boot/`: `boot_a.img`, `vendor_boot.img`,
  `dtbo.img`, `RELEASE`, `SHA256SUMS`, which `omamobile-ingot-boot`'s
  pacman hook sees (it writes only with `AUTO_WRITE=yes`).
- `/usr/share/omamobile/linux-ingot/`: `kernel.release`, `SOURCE`, and the
  board DTB for reference.

`depends=(kmod omamobile-ingot-boot)`, `options=(!strip !debug)`.

## Update flow

1. Stage (above).
2. Build both packages into your local repository:
   `tools/build-packages --local ingot packages/linux-omamobile-ingot packages/omamobile-ingot-boot`.
3. Copy the two package files from `out/ingot/repo/aarch64/` to the phone
   and install them with `sudo pacman -U` (not `tools/repo-push`, which
   copies the maintainer's `out/repo`).
4. `omamobile-ingot-boot preflight`, then `omamobile-ingot-boot write --dry-run`,
   then `sudo omamobile-ingot-boot write`, and copy
   `/var/lib/omamobile/ingot-boot/previous` off the phone.
5. Restart.

Recovery, if the new set does not boot: Volume Down + Power for fastboot;
`fastboot boot` a known-good `boot.img`; `fastboot flash boot_a` a
known-good footered image (and `vendor_boot_a`/`dtbo_a` if they changed);
`fastboot set_active b` returns to LineageOS on slot B, which cannot use
this userdata. See `packages/omamobile-ingot-boot/README.md`.
