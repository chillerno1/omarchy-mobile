#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""ota-payload.py: read partition images out of an A/B OTA's payload.bin.

    ota-payload.py ZIP list
    ota-payload.py ZIP extract OUTDIR PARTITION...

ZIP is an A/B OTA zip whose payload.bin is stored uncompressed (as every
signed OTA's is). Only full payloads: the operations REPLACE, REPLACE_BZ,
REPLACE_XZ, ZERO and DISCARD. Each image written is checked against the
SHA-256 the payload's manifest gives for it. Reads only; run with
python3 -I (the zip is untrusted input).
"""
import bz2
import hashlib
import lzma
import os
import struct
import sys
import zipfile

OP_NAMES = {0: "REPLACE", 1: "REPLACE_BZ", 2: "MOVE", 3: "BSDIFF",
            4: "SOURCE_COPY", 5: "SOURCE_BSDIFF", 6: "ZERO", 7: "DISCARD",
            8: "REPLACE_XZ", 9: "PUFFDIFF", 10: "BROTLI_BSDIFF", 11: "ZUCCHINI",
            12: "LZ4DIFF_BSDIFF", 13: "LZ4DIFF_PUFFDIFF", 14: "REPLACE_ZSTD"}


def varint(b, i):
    v = s = 0
    while True:
        c = b[i]
        i += 1
        v |= (c & 0x7F) << s
        s += 7
        if not c & 0x80:
            return v, i


def fields(b):
    """Protobuf wire format: yield (field number, value)."""
    i = 0
    while i < len(b):
        k, i = varint(b, i)
        f, w = k >> 3, k & 7
        if w == 0:
            v, i = varint(b, i)
        elif w == 2:
            n, i = varint(b, i)
            v = b[i:i + n]
            i += n
        elif w == 1:
            v, i = b[i:i + 8], i + 8
        elif w == 5:
            v, i = b[i:i + 4], i + 4
        else:
            raise SystemExit(f"payload manifest: unsupported wire type {w}")
        yield f, v


def open_payload(zpath):
    z = zipfile.ZipFile(zpath)
    try:
        info = z.getinfo("payload.bin")
    except KeyError:
        raise SystemExit(f"{zpath}: no payload.bin (not an A/B OTA)")
    if info.compress_type != zipfile.ZIP_STORED:
        raise SystemExit(f"{zpath}: payload.bin is compressed in the zip")
    f = open(zpath, "rb")
    f.seek(info.header_offset)
    h = f.read(30)
    if h[:4] != b"PK\x03\x04":
        raise SystemExit(f"{zpath}: bad local header for payload.bin")
    nl, el = struct.unpack("<HH", h[26:30])
    base = info.header_offset + 30 + nl + el
    f.seek(base)
    if f.read(4) != b"CrAU":
        raise SystemExit(f"{zpath}: payload.bin has no CrAU magic")
    ver, msize = struct.unpack(">QQ", f.read(16))
    if ver != 2:
        raise SystemExit(f"{zpath}: payload version {ver}, only 2 is supported")
    sigsize, = struct.unpack(">I", f.read(4))
    manifest = f.read(msize)
    data_base = base + 24 + msize + sigsize
    bs, parts = 4096, []
    for fn, v in fields(manifest):
        if fn == 3:
            bs = v
        elif fn == 13:
            parts.append(v)
    out = {}
    for p in parts:
        name, ops, size, digest = None, [], None, None
        for fn, v in fields(p):
            if fn == 1:
                name = v.decode()
            elif fn == 8:
                ops.append(v)
            elif fn == 7:  # new_partition_info
                for a, b in fields(v):
                    if a == 1:
                        size = b
                    elif a == 2:
                        digest = b
        out[name] = (ops, size, digest)
    return f, data_base, bs, out


def extract(f, data_base, bs, name, ops, size, digest, path):
    with open(path, "wb") as out:
        for op in ops:
            t = off = ln = 0
            dst = []
            for fn, v in fields(op):
                if fn == 1:
                    t = v
                elif fn == 2:
                    off = v
                elif fn == 3:
                    ln = v
                elif fn == 6:
                    sb = nb = 0
                    for a, b in fields(v):
                        if a == 1:
                            sb = b
                        elif a == 2:
                            nb = b
                    dst.append((sb, nb))
            if t in (0, 1, 8):
                f.seek(data_base + off)
                d = f.read(ln)
                if t == 1:
                    d = bz2.decompress(d)
                elif t == 8:
                    d = lzma.decompress(d)
            elif t in (6, 7):
                d = None
            else:
                raise SystemExit(f"{name}: operation {OP_NAMES.get(t, t)} not supported "
                                 "(an incremental payload?)")
            pos = 0
            for sb, nb in dst:
                out.seek(sb * bs)
                if d is None:
                    out.write(b"\0" * (nb * bs))
                else:
                    out.write(d[pos:pos + nb * bs])
                    pos += nb * bs
        if size is not None:
            out.truncate(size)
    if digest:
        h = hashlib.sha256()
        with open(path, "rb") as r:
            for chunk in iter(lambda: r.read(1 << 20), b""):
                h.update(chunk)
        if h.digest() != digest:
            os.unlink(path)
            raise SystemExit(f"{name}: SHA-256 does not match the payload manifest")


def main(argv):
    if len(argv) < 3 or argv[2] not in ("list", "extract") or \
            (argv[2] == "extract" and len(argv) < 5):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    f, data_base, bs, parts = open_payload(argv[1])
    if argv[2] == "list":
        for name, (ops, size, _) in parts.items():
            print(name, size if size is not None else "?", len(ops))
        return 0
    outdir = argv[3]
    for name in argv[4:]:
        if name not in parts:
            raise SystemExit(f"no partition {name} in the payload")
        extract(f, data_base, bs, name, *parts[name], os.path.join(outdir, name + ".img"))
        print(f"wrote {name}.img")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
