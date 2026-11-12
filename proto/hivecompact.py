#!/usr/bin/env python3
"""Prototype: rewrite a registry hive from scratch, tightly packed.

hivex grows hives a lot when adding many keys (SYSTEM 11 MB -> 312 MB). The boot loader
can't load a SYSTEM hive that size. This writes a fresh hive with the same content:
- keys with flags, access bits, timestamps, class names (Lsa boot key lives there!)
- values in original order; > 16344 bytes as big data (db)
- security descriptors (deduplicated, sk list linked)
- subkey lists sorted case-insensitively, lh hashes, ri index for large lists

Usage: hivecompact.py IN OUT
"""
import struct
import sys

BASE = 4096
SEG = 16344
LEAF_MAX = 1000


class Reader:
    def __init__(self, path):
        self.d = open(path, "rb").read()
        self.root = struct.unpack_from("<I", self.d, 0x24)[0]

    def u16(self, o):
        return struct.unpack_from("<H", self.d, o)[0]

    def u32(self, o):
        return struct.unpack_from("<I", self.d, o)[0]

    def cell(self, off):
        c = BASE + off
        return c + 4, abs(struct.unpack_from("<i", self.d, c)[0]) - 4

    def subkeys(self, off):
        c, _ = self.cell(off)
        sig, n = self.d[c:c + 2], self.u16(c + 2)
        if sig in (b"lf", b"lh"):
            return [self.u32(c + 4 + 8 * i) for i in range(n)]
        if sig == b"li":
            return [self.u32(c + 4 + 4 * i) for i in range(n)]
        if sig == b"ri":
            out = []
            for i in range(n):
                out += self.subkeys(self.u32(c + 4 + 4 * i))
            return out
        raise ValueError(f"bad subkey list {sig}")

    def value_data(self, size, off):
        c, csz = self.cell(off)
        if self.d[c:c + 2] == b"db" and size > SEG:
            nseg, lst = self.u16(c + 2), self.u32(c + 4)
            lc, _ = self.cell(lst)
            out = b""
            for i in range(nseg):
                sc, ssz = self.cell(self.u32(lc + 4 * i))
                out += self.d[sc:sc + min(ssz, SEG)]
            return out[:size]
        return self.d[c:c + size]

    def key(self, off):
        c, _ = self.cell(off)
        d = self.d
        assert d[c:c + 2] == b"nk", f"no nk at {off}"
        flags = self.u16(c + 2)
        ts = d[c + 4:c + 12]
        access = self.u32(c + 12)
        nsub, sublist = self.u32(c + 20), self.u32(c + 28)
        nval, vallist = self.u32(c + 36), self.u32(c + 40)
        skoff, classoff = self.u32(c + 44), self.u32(c + 48)
        namelen, classlen = self.u16(c + 72), self.u16(c + 74)
        raw = d[c + 76:c + 76 + namelen]
        name = raw.decode("latin1") if flags & 0x20 else raw.decode("utf-16-le")
        cls = None
        if classlen and classoff != 0xFFFFFFFF:
            cc, _ = self.cell(classoff)
            cls = d[cc:cc + classlen]
        sc, _ = self.cell(skoff)
        sd = d[sc + 20:sc + 20 + self.u32(sc + 16)]
        values = []
        if nval:
            vc, _ = self.cell(vallist)
            for i in range(nval):
                v, _ = self.cell(self.u32(vc + 4 * i))
                vnl, dsize, doff, vtype, vflags = struct.unpack_from("<HIIIH", d, v + 2)
                vraw = d[v + 20:v + 20 + vnl]
                vname = vraw.decode("latin1") if vflags & 1 else vraw.decode("utf-16-le")
                size = dsize & 0x7FFFFFFF
                if dsize & 0x80000000:
                    data = struct.pack("<I", doff)[:size]
                elif size == 0:
                    data = b""
                else:
                    data = self.value_data(size, doff)
                values.append((vname, vtype, data))
        subs = self.subkeys(sublist) if nsub else []
        return {"name": name, "flags": flags, "ts": ts, "access": access, "class": cls,
                "sd": sd, "values": values, "subs": subs}


def up(ch):
    """RtlUpcaseUnicodeChar-like: only 1:1 mappings (Python's 'ß'.upper() is 'SS')."""
    u = ch.upper()
    return u if len(u) == 1 else ch


def upname(name):
    return "".join(up(c) for c in name)


def lh_hash(name):
    h = 0
    for ch in name:
        h = (h * 37 + ord(up(ch))) & 0xFFFFFFFF
    return h


def enc_name(name):
    try:
        return name.encode("latin1"), True
    except UnicodeEncodeError:
        return name.encode("utf-16-le"), False


class Writer:
    def __init__(self):
        self.bins = bytearray()   # hive bins data (offsets relative to start of bins)
        self.hbin_start = 0
        self.hbin_end = 0

    def alloc(self, payload):
        """Append an allocated cell, return its offset."""
        size = (len(payload) + 4 + 7) & ~7
        if len(self.bins) + size > self.hbin_end:
            self._new_hbin(size)
        off = len(self.bins)
        self.bins += struct.pack("<i", -size) + payload + b"\0" * (size - 4 - len(payload))
        return off

    def _new_hbin(self, need):
        if len(self.bins) < self.hbin_end:          # close current hbin with a free cell
            rest = self.hbin_end - len(self.bins)
            self.bins += struct.pack("<i", rest) + b"\0" * (rest - 4)
        hsize = max(4096, (need + 32 + 4095) // 4096 * 4096)
        self.hbin_start = len(self.bins)
        self.hbin_end = self.hbin_start + hsize
        self.bins += b"hbin" + struct.pack("<II", self.hbin_start, hsize) + b"\0" * 20

    def finish(self):
        if len(self.bins) < self.hbin_end:
            rest = self.hbin_end - len(self.bins)
            self.bins += struct.pack("<i", rest) + b"\0" * (rest - 4)

    def patch(self, off, fmt, *vals):
        struct.pack_into(fmt, self.bins, off + 4, *vals)


def load_tree(path):
    """Read a hive into nested dicts: name, flags, ts, access, class, sd, values, subs."""
    r = Reader(path)

    def load(off):
        k = r.key(off)
        k["subs"] = {c["name"].lower(): c for c in (load(x) for x in k["subs"])}
        return k
    return load(r.root), r.d[:BASE]


def write_tree(root_key, base_block, dst):
    """Write a tree from load_tree() as a fresh, compact hive."""
    w = Writer()
    sks = {}          # sd bytes -> [offset, refcount]

    def write_value(name, vtype, data):
        nraw, comp = enc_name(name)
        size = len(data)
        if size <= 4:
            dsize, doff = size | 0x80000000, struct.unpack("<I", data.ljust(4, b"\0"))[0]
        elif size <= SEG:
            dsize, doff = size, w.alloc(data)
        else:
            segs = [w.alloc(data[i:i + SEG].ljust(SEG, b"\0"))   # full-size, like Windows
                    for i in range(0, size, SEG)]
            lst = w.alloc(b"".join(struct.pack("<I", s) for s in segs))
            dsize, doff = size, w.alloc(b"db" + struct.pack("<HI", len(segs), lst))
        return w.alloc(b"vk" + struct.pack("<HIIIHH", len(nraw), dsize, doff, vtype,
                                           1 if comp else 0, 0) + nraw)

    def write_list(entries):
        """entries: [(name, nk_offset)] sorted. Returns list offset."""
        def leaf(chunk):
            body = b"lh" + struct.pack("<H", len(chunk))
            for name, off in chunk:
                body += struct.pack("<II", off, lh_hash(name))
            return w.alloc(body)
        if len(entries) <= LEAF_MAX:
            return leaf(entries)
        leaves = [leaf(entries[i:i + LEAF_MAX]) for i in range(0, len(entries), LEAF_MAX)]
        return w.alloc(b"ri" + struct.pack("<H", len(leaves)) +
                       b"".join(struct.pack("<I", l) for l in leaves))

    count = [0]

    def write_key(k, parent):
        count[0] += 1
        nraw, comp = enc_name(k["name"])
        flags = (k["flags"] & ~0x20 & ~0x02) | (0x20 if comp else 0)   # drop volatile bit
        # placeholder nk, patched after children are written
        nk = w.alloc(b"nk" + b"\0" * 74 + nraw)
        sd = k["sd"]
        if sd not in sks:
            sks[sd] = [w.alloc(b"sk" + struct.pack("<HIIII", 0, 0, 0, 0, len(sd)) + sd), 0]
        sks[sd][1] += 1
        cls_off = w.alloc(k["class"]) if k["class"] else 0xFFFFFFFF
        vals = [write_value(*v) for v in k["values"]]
        val_list = w.alloc(b"".join(struct.pack("<I", v) for v in vals)) if vals else 0xFFFFFFFF
        children = []
        for c in k["subs"].values():
            children.append(write_key(c, nk))
        children.sort(key=lambda x: upname(x[0]).encode("utf-16-le").decode("utf-16-le"))
        sub_list = write_list(children) if children else 0xFFFFFFFF
        max_sub = max((len(n) * 2 for n, _ in children), default=0)
        max_vn = max((len(v[0]) * 2 for v in k["values"]), default=0)
        max_vd = max((len(v[2]) for v in k["values"]), default=0)
        cls_len = len(k["class"]) if k["class"] else 0
        w.patch(nk, "<2sH8sIIIIIIIIIIIIIIIHH", b"nk", flags, k["ts"], k["access"], parent,
                len(children), 0, sub_list, 0xFFFFFFFF, len(vals), val_list,
                sks[sd][0], cls_off, max_sub, 0, max_vn, max_vd, 0, len(nraw), cls_len)
        return k["name"], nk

    w._new_hbin(0)
    _, root = write_key(root_key, 0xFFFFFFFF)
    # link sk records into a circular list, set refcounts
    offs = [v[0] for v in sks.values()]
    for i, (sd, (off, refs)) in enumerate(sks.items()):
        w.patch(off, "<2sHIII", b"sk", 0, offs[i - 1], offs[(i + 1) % len(offs)], refs)
    w.finish()

    base = bytearray(base_block)
    seq = max(struct.unpack_from("<II", base, 4)) + 1
    struct.pack_into("<II", base, 4, seq, seq)
    struct.pack_into("<I", base, 0x24, root)
    struct.pack_into("<I", base, 0x28, len(w.bins))
    struct.pack_into("<I", base, 0x90, 0)          # flags: no pending transactions
    x = 0
    for i in range(0, 508, 4):
        x ^= struct.unpack_from("<I", base, i)[0]
    struct.pack_into("<I", base, 0x1FC, 0xFFFFFFFE if x == 0xFFFFFFFF else (x or 1))
    open(dst, "wb").write(bytes(base) + bytes(w.bins))
    return count[0], len(sks)


def compact(src, dst):
    tree, base = load_tree(src)
    return write_tree(tree, base, dst)


if __name__ == "__main__":
    n, s = compact(sys.argv[1], sys.argv[2])
    print(f"{n} keys, {s} security descriptors")
