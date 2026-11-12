#!/usr/bin/env python3
"""Prototype: recover deleted keys (+ their values) from free cells of a hive.

Deleted keys stay in the hive file as free cells until overwritten. A record is only
used if its signature, sizes and value cells are intact.
"""
import struct

BASE = 4096


class FreeCells:
    def __init__(self, path):
        self.d = d = open(path, "rb").read()
        self.alloc, self.free = {}, {}
        pos = BASE
        while pos < len(d) and d[pos:pos + 4] == b"hbin":
            hsize = struct.unpack_from("<I", d, pos + 8)[0]
            c = pos + 32
            while c < pos + hsize:
                sz = struct.unpack_from("<i", d, c)[0]
                if sz == 0:
                    break
                if d[c + 4:c + 6] == b"nk":
                    (self.free if sz > 0 else self.alloc)[c - BASE] = c
                c += abs(sz)
            pos += hsize

    def u32(self, off):
        return struct.unpack_from("<I", self.d, off)[0]

    def name(self, c):
        flags = struct.unpack_from("<H", self.d, c + 6)[0]
        ln = struct.unpack_from("<H", self.d, c + 4 + 72)[0]
        raw = self.d[c + 80:c + 80 + ln]
        return raw.decode("latin1") if flags & 0x20 else raw.decode("utf-16-le", "replace")

    def is_root(self, c):
        return bool(struct.unpack_from("<H", self.d, c + 6)[0] & 0x4)

    def parent(self, c):
        return self.u32(c + 4 + 16)

    def path(self, off, depth=0):
        c = self.alloc.get(off) or self.free.get(off)
        if c is None or depth > 64:
            return None
        if self.is_root(c):
            return ""
        p = self.path(self.parent(c), depth + 1)
        return None if p is None else p + "\\" + self.name(c)

    def cell(self, off):
        """Return (data, is_free) of the cell at hive offset off, or None."""
        c = BASE + off
        if c + 4 > len(self.d):
            return None
        sz = struct.unpack_from("<i", self.d, c)[0]
        if sz == 0 or c + abs(sz) > len(self.d):
            return None
        return self.d[c + 4:c + abs(sz)], sz > 0

    def values(self, c):
        """Values of the nk record at file offset c; None if any record is broken."""
        count = self.u32(c + 4 + 36)
        if count == 0:
            return []
        if count > 4096:
            return None
        lst = self.cell(self.u32(c + 4 + 40))
        if not lst or len(lst[0]) < 4 * count:
            return None
        out = []
        for i in range(count):
            vk = self.cell(struct.unpack_from("<I", lst[0], 4 * i)[0])
            if not vk or vk[0][:2] != b"vk":
                return None
            v = vk[0]
            nlen, dsize, doff, vtype, flags = struct.unpack_from("<HIIIH", v, 2)
            name = v[20:20 + nlen].decode("latin1") if flags & 1 else \
                v[20:20 + nlen].decode("utf-16-le", "replace")
            size = dsize & 0x7FFFFFFF
            if dsize & 0x80000000:          # data stored inline in the offset field
                data = struct.pack("<I", doff)[:size]
            elif size == 0:
                data = b""
            else:
                dc = self.cell(doff)
                if not dc:
                    return None
                if dc[0][:2] == b"db":       # big data: list of segments
                    nseg, segs = struct.unpack_from("<HI", dc[0], 2)
                    sl = self.cell(segs)
                    if not sl:
                        return None
                    data = b""
                    for j in range(nseg):
                        seg = self.cell(struct.unpack_from("<I", sl[0], 4 * j)[0])
                        if not seg:
                            return None
                        data += seg[0][:16344]
                    data = data[:size]
                else:
                    if len(dc[0]) < size:
                        return None
                    data = dc[0][:size]
            out.append((name, vtype, data))
        return out

    def deleted_keys(self):
        """{path_lower: (path, values)} for free nk records with a resolvable path."""
        out = {}
        for off, c in self.free.items():
            p = self.path(off)
            if not p:
                continue
            vals = self.values(c)
            if vals is None:
                continue
            ts = struct.unpack_from("<Q", self.d, c + 8)[0]
            prev = out.get(p.lower())
            if prev is None or ts > prev[2]:   # keep newest copy of the same key
                out[p.lower()] = (p, vals, ts)
        return out
