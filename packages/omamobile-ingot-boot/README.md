<!-- SPDX-License-Identifier: MIT -->
# omamobile-ingot-boot

Writes the Solana Mobile Saga's (`ingot`, SM8475) boot images to slot A, on
the phone, from the image set that `linux-omamobile-ingot` installs in
`/usr/lib/omamobile/ingot/boot`. It also reads the bootloader's slot flags
and says, in plain words, what the next boots will do.

**Not yet run on a phone.** Everything below is tested offline (`test/all`,
a fake root with regular files for partitions and a synthetic GPT). The
first run on the Saga needs an image whose storage guard leaves `boot_a`,
`vendor_boot_a` and `dtbo_a` writable (built with `--self-update`); on any
other image every write is refused because those partitions are read-only.

On the Saga the slot roles are the reverse of the Pixels': **slot A is
ours, slot B holds LineageOS**, the way back, which this package never
writes. The bootloader takes the kernel, initramfs and command line from
`boot_a` (one header-v4 `boot.img`), the device tree only from
`vendor_boot_a`, and an overlay from `dtbo_a`. This is a separate tool from
`omamobile-boot-update`, which writes slot B on the Pixels and is unchanged.

## Commands

| Command | What it does |
| --- | --- |
| `omamobile-ingot-boot status` | the board, the boot slot, the running release, the installed image set, the three partitions (writable or not), what slot A holds by this tool's record, the saved set, and the slot verdict |
| `omamobile-ingot-boot slots [--json]` | read-only: the slot flags of `boot_a` and `boot_b` and what they mean (below) |
| `omamobile-ingot-boot preflight [--json]` | read-only: every check a write makes, without writing |
| `omamobile-ingot-boot write --dry-run` | the plan (which partitions change); writes nothing anywhere |
| `sudo omamobile-ingot-boot write [--boot-only] [--images DIR]` | checks, saves the partitions that change, writes, reads back; asks you to type `ingot` unless `--yes` |
| `omamobile-ingot-boot rollback --dry-run` | what a rollback would write |
| `sudo omamobile-ingot-boot rollback` | writes the saved set back, through the same checks |
| `omamobile-ingot-boot hook` | what the pacman hook runs: nothing unless `AUTO_WRITE=yes` (below) |

`--boot-only` writes `boot_a` alone (a kernel or initramfs change that
needs no new DTB or overlay). `--images DIR` takes another image set, laid
out as `tools/build-ingot-probe --standalone` writes it: `boot_a.img`,
`vendor_boot.img`, `dtbo.img`, `RELEASE` and `SHA256SUMS`.

## Safety properties

1. **Three partitions, a constant.** `boot_a`, `vendor_boot_a` and
   `dtbo_a` are the only partitions it can write; no option, configuration
   value or file names a partition. Each is found by its GPT name
   (`PARTNAME` in `/sys/class/block/*/uevent`, never a partition number,
   since the Arch root has no `/dev/disk/by-partlabel`) and refused when
   the name is found zero times or more than once, on any disk. Right
   before each write the name, the node and the `ro` flag are checked
   again, and a separate deny check refuses anything ending `_b`,
   `vbmeta*`, `misc`, `devinfo`, `persist*`, `modem*`, `efs*`, `fsg*`,
   `abl*`, `xbl*`, `userdata`, `super`, a whole-disk node, or any name
   that is not one of the three.
2. **The storage guard decides.** It never runs `blockdev --setrw`, never
   writes a sysfs `ro` or `force_ro`, never writes the partition table or
   the slot flags, never runs fastboot and never reboots. A partition
   whose `ro` reads 1 is a refusal: the running image's storage guard keeps
   it read-only (boot an image built with `--self-update`).
3. **The Saga, from slot A.** The first string of
   `/proc/device-tree/compatible` must be `osom,ingot`, and
   `/proc/bootconfig` or `/proc/cmdline` must say
   `androidboot.slot_suffix=_a` (quoted or not); a boot that names slot B,
   or no slot, is refused.
4. **The images are checked by structure** (`lib/ingot-images.sh`, which
   `linux-omamobile-ingot`'s `stage` uses too): `SHA256SUMS` lists exactly
   the three images and `RELEASE`, and each matches; `boot_a.img` starts
   with `ANDROID!`, is header version 4, is exactly the size of `boot_a`
   and ends with an AVB footer (`AVBf` at the start of the last 64 bytes);
   `vendor_boot.img` starts with `VNDRBOOT`; `dtbo.img` starts with
   `d7 b7 ab 1e`; none is larger than its partition (sizes from sysfs).
   `RELEASE` must name a release with `/usr/lib/modules/<release>/modules.dep`:
   a kernel without its modules boots without its GPU and Wi-Fi.
5. **Battery:** below 30% and not charging is a refusal. A phone with no
   battery reading yet (no battery driver) gets a warning, not a refusal.
6. **Only what changes, saved first, read back.** A partition that already
   holds its image (sha256 over the image's length) is skipped. Before the
   first byte is written, the whole partitions that will change are saved
   to `/var/lib/omamobile/ingot-boot/previous/` with `SHA256SUMS`, `SIZES`,
   `RELEASE` (the running kernel's) and `BOOTED`, after a free-space check.
   An existing saved set is replaced only while slot A holds what booted
   (none of the three written since this boot: field 7 of
   `/sys/class/block/<part>/stat` is 0); otherwise it is kept. Each image
   is written with `dd conv=fsync` and read back by sha256; a mismatch stops
   with an error that says to run `omamobile-ingot-boot rollback` **before
   restarting**. What was written is recorded in `current/`.
7. **`--dry-run`** writes nothing, not even a lock or state file. A manual
   `write` or `rollback` asks you to type `ingot` (or needs `--yes`). One
   run at a time (`flock`). It never restarts the phone: it says a restart
   is needed.
8. **The hook is opt-in.** `90-omamobile-ingot-boot.hook` runs after a
   transaction that installs or upgrades `usr/lib/omamobile/ingot/boot/*`
   (after `60-depmod.hook`). It does nothing unless
   `/etc/omamobile/ingot-boot.conf` says `AUTO_WRITE=yes`; that file is read
   as data, never sourced, and no package ships it. When on, it runs
   `write --yes`. A failure prints its error in pacman's output; pacman's
   transaction is already complete (a post-transaction hook cannot undo
   it), and slot A is either untouched or, after a failed read-back, to be
   rolled back before restarting.

## Slot flags

The flags below are **the bootloader's behaviour as its public reference
source describes it, to be confirmed on the phone**. They live in the GPT
entry attributes of `boot_a` and `boot_b` on UFS LUN 4: bits 48-49
priority, 50 active, 51-53 tries left, 54 successful, 55 unbootable.

- A slot marked successful boots without counting.
- An active slot that is not marked successful loses one try per normal
  boot (not in fastboot mode, and not for `fastboot boot`). At zero the
  bootloader marks it unbootable and switches to the other slot **only if**
  that one is successful and not unbootable; otherwise it stops in
  fastboot.
- `fastboot set_active X` and `fastboot flash boot_X` clear X's successful
  flag and give it 7 tries. Writing the partition from Linux, as this tool
  does, leaves the flags alone.

`omamobile-ingot-boot slots` opens the disk that holds `boot_a` read-only,
reads its GPT (4096-byte blocks, the header at LBA 1, both CRCs checked)
and prints the flags and a verdict:

| State | Verdict | Exit |
| --- | --- | --- |
| A successful | boots without counting | 0 |
| A not successful, B not eligible | N normal boots left, then the phone stops in fastboot; `fastboot set_active a` from a computer gives 7 more | 0, or 2 when N is 2 or less |
| A not successful, B successful and bootable | **DANGER**: after N more boots the bootloader switches to slot B, whose system cannot use this userdata. From fastboot: `fastboot set_active b` then `fastboot set_active a` in the same session, then check `fastboot getvar all` | 3 |
| A not active or unbootable | the next boot goes to B (DANGER, 3) or stops in fastboot (2) | 2 or 3 |
| disk node missing or unreadable, no GPT, a bad CRC | says so, no guess | 1 |

`omamobile-ingot-slot-check.service` (enabled) runs `slots --service` once
per boot: the verdict in the journal (`journalctl -t omamobile-ingot-slots`),
at warning level when tries are low or in the danger state, and in
`/run/omamobile/ingot-slots.json`. It is read-only and its failure is
ignored. Nothing in this package changes slot flags; that is a separate
decision.

## Updating the kernel

On the laptop (see `packages/linux-omamobile-ingot/README.md`):

```sh
tools/build-ingot-probe --standalone ... --out IMAGES      # boot_a.img, vendor_boot.img, dtbo.img, RELEASE, SHA256SUMS
KERNEL_DIR=<kernel tree> packages/linux-omamobile-ingot/stage KERNEL_OUT IMAGES
tools/build-packages --local ingot packages/linux-omamobile-ingot packages/omamobile-ingot-boot
```

On the phone, after installing both packages from that local repository:

```sh
omamobile-ingot-boot preflight
omamobile-ingot-boot write --dry-run
sudo omamobile-ingot-boot write
scp -r root@<phone>:/var/lib/omamobile/ingot-boot/previous ./ingot-previous   # from the laptop, before restarting
```

then restart.

## Recovery

If the new images don't boot, this tool can't run, and the saved set on
`userdata` is out of reach; the way back is from a computer:

1. Hold **Volume Down + Power** until the phone is in fastboot.
2. `fastboot boot <known-good boot.img>` boots a known-good kernel once,
   without writing anything and without counting a try.
3. `fastboot flash boot_a <known-good footered boot_a.img>` (for example
   the `boot_a.img` copied off the phone from `previous/`) writes it back;
   `vendor_boot_a` and `dtbo_a` the same way if they changed. Flashing
   clears slot A's successful flag and gives it 7 tries.
4. `fastboot set_active b` returns to LineageOS on slot B, but that system
   cannot use this userdata: it is a way to a working phone, not back to
   this install.

## Files

- `/usr/lib/omamobile/ingot/boot/`: the image set (from `linux-omamobile-ingot`).
- `/var/lib/omamobile/ingot-boot/previous/`: the saved partitions, about
  216 MiB when all three change; `current/`: what was last written;
  `incomplete`: a write that stopped.
- `/etc/omamobile/ingot-boot.conf`: `AUTO_WRITE=yes|no` (absent means no).
- `/run/omamobile/ingot-slots.json`: the slot verdict of this boot.
