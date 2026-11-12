#!/usr/bin/env python3
"""Prototype: convert values larger than 16344 bytes into "big data" (db) records.

hivex writes such values as one plain cell. Windows (hive format 1.4+) requires a db
record (list of <=16344-byte segments) and blanks the value otherwise. This post-processor
appends one hbin holding the segments, the segment list and the db record, points the
value at it and frees the old cell.

Usage: bigdata.py HIVE   (in place)
"""
import struct
import sys

import hivex

BASE = 4096
SEG = 16344


def align8(n):
    return (n + 7) & ~7


def big_values(path):
    """[(vk_file_offset, data_size)] of values stored as plain cells > SEG bytes."""
    raw = open(path, "rb").read()
    h = hivex.Hivex(path)
    out = []

    def walk(n):
        for v in h.node_values(n):
            dsize, doff = struct.unpack_from("<II", raw, v + 8)
            size = dsize & 0x7FFFFFFF
            if not dsize & 0x80000000 and size > SEG and raw[BASE + doff + 4:BASE + doff + 6] != b"db":
                out.append((v, size))
        for c in h.node_children(n):
            walk(c)
    walk(h.root())
    return out


def checksum(base):
    x = 0
    for i in range(0, 508, 4):
        x ^= struct.unpack_from("<I", base, i)[0]
    return 0xFFFFFFFE if x == 0xFFFFFFFF else (1 if x == 0 else x)


def fix(path):
    todo = big_values(path)
    if not todo:
        return 0
    d = bytearray(open(path, "rb").read())
    bins_size = struct.unpack_from("<I", d, 0x28)[0]
    del d[BASE + bins_size:]

    # Build the new hbin body.
    cells = bytearray()
    hbin_off = bins_size            # offset of new hbin relative to hive bins start
    cursor = hbin_off + 32          # next free cell offset (relative)
    patches = []                    # (vk, db_cell_offset, old_data_offset)
    for vk, size in todo:
        doff = struct.unpack_from("<I", d, vk + 12)[0]
        data = bytes(d[BASE + doff + 4:BASE + doff + 4 + size])
        seg_offs = []
        for i in range(0, size, SEG):
            chunk = data[i:i + SEG]
            csz = align8(len(chunk) + 4)
            cells += struct.pack("<i", -csz) + chunk + b"\0" * (csz - 4 - len(chunk))
            seg_offs.append(cursor)
            cursor += csz
        lst = b"".join(struct.pack("<I", o) for o in seg_offs)
        csz = align8(len(lst) + 4)
        cells += struct.pack("<i", -csz) + lst + b"\0" * (csz - 4 - len(lst))
        list_off = cursor
        cursor += csz
        db = b"db" + struct.pack("<HI", len(seg_offs), list_off)
        csz = align8(len(db) + 4)
        cells += struct.pack("<i", -csz) + db + b"\0" * (csz - 4 - len(db))
        patches.append((vk, cursor, doff))
        cursor += csz

    used = 32 + len(cells)
    hsize = (used + 4095) // 4096 * 4096
    if hsize - used:
        cells += struct.pack("<i", hsize - used) + b"\0" * (hsize - used - 4)   # free cell
    hdr = b"hbin" + struct.pack("<II", hbin_off, hsize) + b"\0" * 8 + b"\0" * 8 + b"\0" * 4
    d += hdr + cells

    for vk, db_off, old in patches:
        struct.pack_into("<I", d, vk + 12, db_off)
        sz = struct.unpack_from("<i", d, BASE + old)[0]
        struct.pack_into("<i", d, BASE + old, abs(sz))          # mark old cell free

    struct.pack_into("<I", d, 0x28, bins_size + hsize)
    struct.pack_into("<I", d, 0x1FC, checksum(d))
    open(path, "wb").write(d)
    return len(patches)


if __name__ == "__main__":
    print(f"converted {fix(sys.argv[1])} value(s) to big data")
