#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""lp-metadata.py: read the logical-partition (LP) metadata of a `super`
partition, read-only, from a block device or an image file.

    lp-metadata.py SUPER [--slot b] [--json] NAME...
        the extents of each named logical partition in that slot's
        metadata (NAME may be given with or without the _<slot> suffix):
          lp MAJOR.MINOR slot=N logical_block_size=B super_bytes=S
          part NAME SECTORS START,COUNT [START,COUNT ...]
        START is the first 512-byte sector on SUPER, COUNT a number of
        sectors; the extents are in order, to be read one after the other.
    lp-metadata.py SUPER [--slot b] --list
        every partition in that slot's metadata:
          part NAME SECTORS TYPES (linear, zero or other, per extent)

The slot letter picks the metadata slot (a = 0, b = 1, ...). It checks the
geometry's magic and SHA-256, the metadata header's magic, version and
SHA-256, the tables' SHA-256, every table's bounds and entry size, and each
named partition: found exactly once, only LINEAR extents, all on the one
block device (super itself) and inside it. Anything else is refused (exit
1, the reason on stderr): a ZERO extent, a partition spread over another
block device, a damaged copy. Only the primary geometry and metadata are
read; a backup that differs is reported, never used.

Nothing is opened for writing. Run with python3 -I: the bytes are untrusted
input. tests/ingot-fp-provision builds a synthetic super image and checks
this reader against it; tools/ingot-fp-provision runs it on the phone
(the program on stdin, `python3 -I - /dev/sdX ...`).
"""
import hashlib
import json
import struct
import sys

SECTOR = 512
LP_PARTITION_RESERVED_BYTES = 4096
GEOMETRY_MAGIC = 0x616C4467
GEOMETRY_SIZE = 4096
GEOMETRY_STRUCT = 52  # magic, struct_size, checksum[32], max_size, slot_count, block_size
HEADER_MAGIC = 0x414C5030
HEADER_MAJOR = 10
HEADER_MIN_SIZE = 128  # v10.0/10.1; v10.2 adds flags and padding to 256
PARTITION_ENTRY = 52
EXTENT_ENTRY = 24
BLOCK_DEVICE_ENTRY = 64
TARGET_LINEAR = 0
TARGET_ZERO = 1


class LpError(Exception):
    pass


def _name(raw):
    name = raw.split(b"\0", 1)[0]
    try:
        return name.decode("ascii")
    except UnicodeDecodeError:
        raise LpError(f"a name that isn't ASCII: {name!r}")


def _read(f, offset, size):
    f.seek(offset)
    data = f.read(size)
    if len(data) != size:
        raise LpError(f"short read: {len(data)} of {size} bytes at {offset}")
    return data


def _geometry(raw, where):
    magic, struct_size = struct.unpack_from("<II", raw, 0)
    if magic != GEOMETRY_MAGIC:
        raise LpError(f"no LP geometry at byte {where} (magic {magic:#x}): not a super partition")
    if struct_size < GEOMETRY_STRUCT or struct_size > GEOMETRY_SIZE:
        raise LpError(f"geometry at byte {where}: struct_size {struct_size}")
    want = raw[8:40]
    body = bytearray(raw[:struct_size])
    body[8:40] = bytes(32)
    if hashlib.sha256(body).digest() != want:
        raise LpError(f"geometry at byte {where}: checksum mismatch")
    max_size, slot_count, block_size = struct.unpack_from("<III", raw, 40)
    if max_size == 0 or max_size % SECTOR or slot_count == 0 or block_size == 0 or block_size % SECTOR:
        raise LpError(f"geometry at byte {where}: metadata_max_size {max_size}, "
                      f"slot count {slot_count}, logical_block_size {block_size}")
    return {"metadata_max_size": max_size, "metadata_slot_count": slot_count,
            "logical_block_size": block_size, "raw": bytes(raw[:struct_size])}


def slot_index(letter):
    if len(letter) != 1 or not "a" <= letter <= "z":
        raise LpError(f"slot {letter!r}: a single letter, a = 0, b = 1")
    return ord(letter) - ord("a")


def read_metadata(path, slot):
    """The partitions of metadata slot `slot` (an index) in the super
    partition or image at `path`, checked. Returns a dict: version, slot,
    logical_block_size, block_devices [{name, size, first_logical_sector}],
    partitions [{name, attributes, extents [(num_sectors, type, data, source)]}],
    and warnings (strings)."""
    warnings = []
    with open(path, "rb") as f:
        geo = _geometry(_read(f, LP_PARTITION_RESERVED_BYTES, GEOMETRY_SIZE), LP_PARTITION_RESERVED_BYTES)
        backup_at = LP_PARTITION_RESERVED_BYTES + GEOMETRY_SIZE
        try:
            backup = _geometry(_read(f, backup_at, GEOMETRY_SIZE), backup_at)
            if backup["raw"] != geo["raw"]:
                warnings.append(f"the backup geometry at byte {backup_at} differs from the primary (primary used)")
        except LpError as e:
            warnings.append(f"backup geometry: {e} (primary used)")
        max_size = geo["metadata_max_size"]
        if slot >= geo["metadata_slot_count"]:
            raise LpError(f"metadata slot {slot} asked for, the geometry has {geo['metadata_slot_count']}")
        base = LP_PARTITION_RESERVED_BYTES + 2 * GEOMETRY_SIZE + slot * max_size
        md = _read(f, base, max_size)

    magic, major, minor, header_size = struct.unpack_from("<IHHI", md, 0)
    if magic != HEADER_MAGIC:
        raise LpError(f"metadata slot {slot}: no header (magic {magic:#x})")
    if major != HEADER_MAJOR:
        raise LpError(f"metadata slot {slot}: version {major}.{minor}, this reader knows {HEADER_MAJOR}.x")
    if header_size < HEADER_MIN_SIZE or header_size > max_size:
        raise LpError(f"metadata slot {slot}: header_size {header_size}")
    header = bytearray(md[:header_size])
    want = bytes(header[12:44])
    header[12:44] = bytes(32)
    if hashlib.sha256(header).digest() != want:
        raise LpError(f"metadata slot {slot}: header checksum mismatch")
    tables_size, = struct.unpack_from("<I", md, 44)
    if header_size + tables_size > max_size:
        raise LpError(f"metadata slot {slot}: tables_size {tables_size} past metadata_max_size {max_size}")
    tables = md[header_size:header_size + tables_size]
    if hashlib.sha256(tables).digest() != md[48:80]:
        raise LpError(f"metadata slot {slot}: tables checksum mismatch")

    def table(at, entry, what):
        offset, num, size = struct.unpack_from("<III", md, at)
        if size != entry:
            raise LpError(f"metadata slot {slot}: {what} entries are {size} bytes, expected {entry}")
        if offset + num * size > tables_size:
            raise LpError(f"metadata slot {slot}: the {what} table runs past the tables")
        return [tables[offset + i * size:offset + (i + 1) * size] for i in range(num)]

    block_devices = []
    for raw in table(116, BLOCK_DEVICE_ENTRY, "block device"):
        first, _align, _align_off, size = struct.unpack_from("<QIIQ", raw, 0)
        block_devices.append({"name": _name(raw[24:60]), "size": size, "first_logical_sector": first})
    if not block_devices:
        raise LpError(f"metadata slot {slot}: no block devices")
    extents = [struct.unpack_from("<QIQI", raw, 0) for raw in table(92, EXTENT_ENTRY, "extent")]
    partitions = []
    for raw in table(80, PARTITION_ENTRY, "partition"):
        attributes, first, num, _group = struct.unpack_from("<IIII", raw, 36)
        if first + num > len(extents):
            raise LpError(f"metadata slot {slot}: partition {_name(raw[:36])} has extents past the table")
        partitions.append({"name": _name(raw[:36]), "attributes": attributes,
                           "extents": extents[first:first + num]})
    return {"version": f"{major}.{minor}", "slot": slot,
            "logical_block_size": geo["logical_block_size"],
            "block_devices": block_devices, "partitions": partitions, "warnings": warnings}


def linear_extents(md, name):
    """[(start_sector, num_sectors), ...] for partition `name`, in order;
    LpError unless every extent is LINEAR on block device 0 and inside it."""
    found = [p for p in md["partitions"] if p["name"] == name]
    if len(found) != 1:
        raise LpError(f"{name}: found {len(found)} times in metadata slot {md['slot']}")
    dev = md["block_devices"][0]
    dev_sectors = dev["size"] // SECTOR
    out = []
    for i, (num, kind, data, source) in enumerate(found[0]["extents"]):
        if kind == TARGET_ZERO:
            raise LpError(f"{name}: extent {i} is a ZERO extent (no data on the device); refusing")
        if kind != TARGET_LINEAR:
            raise LpError(f"{name}: extent {i} has target type {kind}, not LINEAR; refusing")
        if source != 0:
            raise LpError(f"{name}: extent {i} is on block device {source}, not {dev['name']}; refusing")
        if num == 0 or data < dev["first_logical_sector"] or data + num > dev_sectors:
            raise LpError(f"{name}: extent {i} ({data},{num}) is outside {dev['name']} "
                          f"({dev['first_logical_sector']}..{dev_sectors}); refusing")
        out.append((data, num))
    if not out:
        raise LpError(f"{name}: no extents (an empty partition)")
    return out


def main(argv):
    args, names, slot_letter, as_json, listing = list(argv), [], "b", False, False
    if not args or args[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0 if args else 2
    path = args.pop(0)
    while args:
        a = args.pop(0)
        if a == "--slot" and args:
            slot_letter = args.pop(0)
        elif a == "--json":
            as_json = True
        elif a == "--list":
            listing = True
        elif a.startswith("-"):
            raise LpError(f"unknown option {a}")
        else:
            names.append(a)
    if not names and not listing:
        raise LpError("name the partitions (or --list)")
    suffix = "_" + slot_letter
    md = read_metadata(path, slot_index(slot_letter))
    for w in md["warnings"]:
        print(f"lp-metadata.py: warning: {w}", file=sys.stderr)
    dev = md["block_devices"][0]
    if listing:
        for p in md["partitions"]:
            kinds = ",".join({TARGET_LINEAR: "linear", TARGET_ZERO: "zero"}.get(e[1], "other")
                             for e in p["extents"]) or "-"
            print(f"part {p['name']} {sum(e[0] for e in p['extents'])} {kinds}")
        return 0
    result = []
    for n in names:
        full = n if n.endswith(suffix) else n + suffix
        ext = linear_extents(md, full)
        result.append({"name": full, "sectors": sum(c for _, c in ext), "extents": ext})
    if as_json:
        print(json.dumps({"version": md["version"], "slot": md["slot"],
                          "logical_block_size": md["logical_block_size"],
                          "super_bytes": dev["size"], "partitions": result}))
    else:
        print(f"lp {md['version']} slot={md['slot']} logical_block_size={md['logical_block_size']} "
              f"super_bytes={dev['size']}")
        for r in result:
            print(f"part {r['name']} {r['sectors']} " + " ".join(f"{s},{c}" for s, c in r["extents"]))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (LpError, OSError) as e:
        print(f"lp-metadata.py: {e}", file=sys.stderr)
        sys.exit(1)
