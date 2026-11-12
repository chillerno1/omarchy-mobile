#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""fat16.py: list or copy files out of a FAT16 image, read-only.

    fat16.py IMG ls [DIR]          one line per entry: d|-, size, name
    fat16.py IMG get PATH OUT      copy one file out

Long file names are read; case is ignored when looking a name up. Run
with python3 -I (the image is untrusted input).
"""
import struct
import sys


class Fat16:
    def __init__(self, path):
        self.img = open(path, "rb")
        bs = self.img.read(512)
        if bs[510:512] != b"\x55\xaa":
            raise SystemExit(f"{path}: no FAT boot sector")
        self.bps, self.spc, rsv, nfat, self.nroot = struct.unpack_from("<HBHBH", bs, 11)
        spf, = struct.unpack_from("<H", bs, 22)
        if not self.bps or not self.spc or not spf:
            raise SystemExit(f"{path}: not FAT12/16 (FAT32 is not supported)")
        self.root_off = (rsv + nfat * spf) * self.bps
        self.data_off = self.root_off + self.nroot * 32
        self.img.seek(rsv * self.bps)
        self.fat = self.img.read(spf * self.bps)

    def chain(self, c):
        out, seen = [], set()
        while 2 <= c < 0xFFF0:
            if c in seen:
                raise SystemExit("FAT chain loops")
            seen.add(c)
            out.append(c)
            c = struct.unpack_from("<H", self.fat, c * 2)[0]
        return out

    def read_chain(self, c):
        csize = self.spc * self.bps
        parts = []
        for k in self.chain(c):
            self.img.seek(self.data_off + (k - 2) * csize)
            parts.append(self.img.read(csize))
        return b"".join(parts)

    @staticmethod
    def entries(raw):
        lfn = []
        for i in range(0, len(raw), 32):
            e = raw[i:i + 32]
            if len(e) < 32 or e[0] == 0:
                break
            if e[0] == 0xE5:
                lfn = []
                continue
            if e[11] == 0x0F:
                lfn.insert(0, (e[1:11] + e[14:26] + e[28:32]).decode("utf-16le", "replace"))
                continue
            if lfn:
                name = "".join(lfn).split("\0")[0]
            else:
                base = e[0:8].decode("latin1").strip()
                ext = e[8:11].decode("latin1").strip()
                name = base + ("." + ext if ext else "")
            lfn = []
            if e[11] & 8:  # volume label
                continue
            yield name, bool(e[11] & 16), struct.unpack_from("<H", e, 26)[0], \
                struct.unpack_from("<I", e, 28)[0]

    def root(self):
        self.img.seek(self.root_off)
        return self.img.read(self.nroot * 32)

    def lookup(self, path):
        raw = self.root()
        comps = [p for p in path.split("/") if p]
        for n, comp in enumerate(comps):
            for name, is_dir, c, size in self.entries(raw):
                if name.lower() == comp.lower():
                    if is_dir:
                        raw = self.read_chain(c)
                        break
                    if n != len(comps) - 1:
                        raise SystemExit(f"not a directory: {comp}")
                    return ("file", c, size)
            else:
                raise SystemExit(f"not found: {path}")
        return ("dir", raw, 0)


def main(argv):
    if len(argv) < 3 or argv[2] not in ("ls", "get") or (argv[2] == "get" and len(argv) != 5):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    fs = Fat16(argv[1])
    if argv[2] == "ls":
        kind, raw, _ = fs.lookup(argv[3] if len(argv) > 3 else "/")
        if kind != "dir":
            raise SystemExit("not a directory")
        for name, is_dir, _, size in fs.entries(raw):
            if name in (".", ".."):
                continue
            print(f"{'d' if is_dir else '-'} {size} {name}")
        return 0
    kind, c, size = fs.lookup(argv[3])
    if kind != "file":
        raise SystemExit(f"not a file: {argv[3]}")
    data = fs.read_chain(c)[:size] if size else b""
    if len(data) != size:
        raise SystemExit(f"{argv[3]}: short read ({len(data)} of {size} bytes)")
    with open(argv[4], "wb") as out:
        out.write(data)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
