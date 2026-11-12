# SPDX-License-Identifier: MIT
# shellcheck shell=bash disable=SC2034 # the constants are for the scripts that source this
# The Solana Mobile Saga's (ingot) boot image set, as tools/build-ingot-probe
# --standalone writes it into slot-a/ (tools/ingot-boot-set), checked by its
# structure alone. Sourced by
# omamobile-ingot-boot on the phone and by linux-omamobile-ingot's ./stage
# on the laptop, so both refuse the same images.
#
# The set is one directory:
#   boot_a.img       boot.img (header v4: kernel, initramfs, command line)
#                    with an AVB hash footer, padded to boot_a's size
#   vendor_boot.img  the DTB (the bootloader takes it only from vendor_boot_a)
#   dtbo.img         the overlay table for dtbo_a
#   RELEASE          one line: the kernel release inside boot_a.img
#   SHA256SUMS       the four files above
#
# Each function prints nothing and returns 0 when the check passes, or
# prints one line saying why and returns 1.

# The image file -> the partition it goes to. The writer's only targets;
# nothing else in the tool can name a partition.
declare -gA IB_TARGET=([boot_a.img]=boot_a [vendor_boot.img]=vendor_boot_a [dtbo.img]=dtbo_a)
IB_IMAGES="boot_a.img vendor_boot.img dtbo.img"
# The partitions' sizes on the Saga (UFS LUN 4); the phone's own sysfs sizes
# are what the writer compares against, these are for the laptop
IB_BOOT_A_BYTES=$((0x6000000))
IB_VENDOR_BOOT_A_BYTES=$((0x6000000))
IB_DTBO_A_BYTES=$((0x1800000))
# A kernel release as the kernel names it: letters, digits, . + _ -
IB_RELEASE_RE='^[0-9]+\.[0-9]+[A-Za-z0-9._+-]*$'

# ib_hex FILE OFFSET COUNT: COUNT bytes at OFFSET, as lowercase hex
ib_hex() { od -An -tx1 -v -j "$2" -N "$3" "$1" 2>/dev/null | tr -d ' \n'; }
# ib_u32 FILE OFFSET: a little-endian u32
ib_u32() { od -An -tu4 --endian=little -j "$2" -N 4 "$1" 2>/dev/null | tr -d ' \n'; }
ib_size() { stat -c %s "$1" 2>/dev/null; }

# ib_check_sums DIR: SHA256SUMS lists exactly the three images and RELEASE,
# by plain names, and every one matches
ib_check_sums() {
  local d=$1 names
  [[ -f $d/SHA256SUMS && ! -L $d/SHA256SUMS ]] || { echo "no $d/SHA256SUMS"; return 1; }
  if grep -vqE '^[0-9a-f]{64}  (boot_a\.img|vendor_boot\.img|dtbo\.img|RELEASE)$' "$d/SHA256SUMS"; then
    echo "$d/SHA256SUMS has a line that is not '<sha256>  <boot_a.img|vendor_boot.img|dtbo.img|RELEASE>'"
    return 1
  fi
  names=$(awk '{print $2}' "$d/SHA256SUMS" | LC_ALL=C sort | tr '\n' ' ')
  [[ $names == "RELEASE boot_a.img dtbo.img vendor_boot.img " ]] \
    || { echo "$d/SHA256SUMS must list boot_a.img, vendor_boot.img, dtbo.img and RELEASE once each (it lists: $names)"; return 1; }
  local f
  for f in $IB_IMAGES RELEASE; do
    [[ -f $d/$f && ! -L $d/$f ]] || { echo "$d/$f is missing or not a regular file"; return 1; }
  done
  (cd "$d" && sha256sum --quiet --strict -c SHA256SUMS >/dev/null 2>&1) || { echo "$d fails its SHA256SUMS"; return 1; }
}

# ib_release DIR: print the release RELEASE names (one line, a release name)
ib_release() {
  local d=$1 rel n
  n=$(wc -l < "$d/RELEASE" 2>/dev/null || echo 0)
  rel=$(head -1 "$d/RELEASE" 2>/dev/null || true)
  [[ $n == 1 && $rel =~ $IB_RELEASE_RE && $rel != *..* ]] || { echo "$d/RELEASE is not one line naming a kernel release"; return 1; }
  echo "$rel"
}

# ib_check_boot FILE BYTES: header v4 boot image with an AVB footer, exactly
# BYTES long (the footer must sit at the partition's end)
ib_check_boot() {
  local f=$1 bytes=$2 size v
  size=$(ib_size "$f")
  [[ $(ib_hex "$f" 0 8) == 414e44524f494421 ]] || { echo "${f##*/} does not start with ANDROID! (not a boot image)"; return 1; }
  v=$(ib_u32 "$f" 40)
  [[ $v == 4 ]] || { echo "${f##*/} is boot image header version ${v:-?}, not 4"; return 1; }
  [[ $size == "$bytes" ]] || { echo "${f##*/} is $size bytes; boot_a is $bytes, and the AVB footer must be at its end"; return 1; }
  [[ $(ib_hex "$f" $((size - 64)) 4) == 41564266 ]] || { echo "${f##*/} has no AVB footer (AVBf) in its last 64 bytes"; return 1; }
}

# ib_check_vendor_boot FILE MAX
ib_check_vendor_boot() {
  local f=$1 max=$2 size
  size=$(ib_size "$f")
  [[ $(ib_hex "$f" 0 8) == 564e4452424f4f54 ]] || { echo "${f##*/} does not start with VNDRBOOT (not a vendor_boot image)"; return 1; }
  ((size <= max)) || { echo "${f##*/} is $size bytes, larger than vendor_boot_a ($max)"; return 1; }
}

# ib_check_dtbo FILE MAX
ib_check_dtbo() {
  local f=$1 max=$2 size
  size=$(ib_size "$f")
  [[ $(ib_hex "$f" 0 4) == d7b7ab1e ]] || { echo "${f##*/} does not start with d7 b7 ab 1e (not a dtbo image)"; return 1; }
  ((size <= max)) || { echo "${f##*/} is $size bytes, larger than dtbo_a ($max)"; return 1; }
}

# ib_check_image NAME FILE PARTITION_BYTES: the check for that image
ib_check_image() {
  case $1 in
    boot_a.img) ib_check_boot "$2" "$3" ;;
    vendor_boot.img) ib_check_vendor_boot "$2" "$3" ;;
    dtbo.img) ib_check_dtbo "$2" "$3" ;;
    *) echo "$1 is not one of the Saga's boot images"; return 1 ;;
  esac
}

# ib_kernel_of BOOT_IMG OUT: the kernel a header v4 boot image carries
# (a 4096-byte header page, kernel_size u32 at offset 8, the kernel from 4096)
ib_kernel_of() {
  local n
  n=$(ib_u32 "$1" 8)
  [[ $n =~ ^[0-9]+$ && $n != 0 ]] || { echo "${1##*/}: no kernel size in its header"; return 1; }
  tail -c +4097 "$1" | head -c "$n" > "$2"
  [[ $(ib_size "$2") == "$n" ]] || { echo "${1##*/}: shorter than its kernel ($n bytes)"; return 1; }
}
