#!/usr/bin/env python3
"""Prototype: check structural fields Windows relies on but hivex may not maintain:
- nk max subkey name len / max value name len / max value data len
- lh hash values in subkey lists
Usage: hivecheck.py HIVE"""
import struct, sys, collections
B = 4096
d = open(sys.argv[1], "rb").read()
u16 = lambda o: struct.unpack_from("<H", d, o)[0]
u32 = lambda o: struct.unpack_from("<I", d, o)[0]

def cell(off):
    c = B + off
    return c + 4, abs(struct.unpack_from("<i", d, c)[0]) - 4

def nk_name(c):
    flags, ln = u16(c + 2), u16(c + 72)
    raw = d[c + 76:c + 76 + ln]
    return (raw.decode("latin1") if flags & 0x20 else raw.decode("utf-16-le")), ln, flags

def lh_hash(name):
    h = 0
    for ch in name:
        h = (h * 37 + ord(ch.upper())) & 0xFFFFFFFF
    return h

def subkeys(listoff):
    c, _ = cell(listoff)
    sig, n = d[c:c + 2], u16(c + 2)
    out = []
    if sig in (b"lf", b"lh"):
        for i in range(n):
            out.append((u32(c + 4 + 8 * i), u32(c + 8 + 8 * i), sig))
    elif sig == b"li":
        out = [(u32(c + 4 + 4 * i), None, sig) for i in range(n)]
    elif sig == b"ri":
        for i in range(n):
            out += subkeys(u32(c + 4 + 4 * i))
    return out

problems = collections.Counter(); examples = collections.defaultdict(list)
root = u32(0x24)
stack = [(root, "")]
seen = 0
while stack:
    off, path = stack.pop()
    c, _ = cell(off)
    seen += 1
    nsub, sublist = u32(c + 20), u32(c + 28)
    nval, vallist = u32(c + 36), u32(c + 40)
    st_maxsub, st_maxval, st_maxdata = u32(c + 52) & 0xFFFF, u32(c + 60), u32(c + 64)
    real_maxsub = 0
    if nsub:
        for koff, h, sig in subkeys(sublist):
            kc, _ = cell(koff)
            nm, ln, flags = nk_name(kc)
            real_maxsub = max(real_maxsub, len(nm) * 2)
            if sig == b"lh" and h != lh_hash(nm):
                problems["lh hash wrong"] += 1; examples["lh hash wrong"].append(path + "\\" + nm)
            stack.append((koff, path + "\\" + nm))
    real_maxval = real_maxdata = 0
    if nval:
        vc, _ = cell(vallist)
        for i in range(nval):
            vk, _ = cell(u32(vc + 4 * i))
            nlen, dsize, flags = u16(vk + 2), u32(vk + 4), u16(vk + 16)
            real_maxval = max(real_maxval, nlen * (1 if flags & 1 else 1) * (2 if flags & 1 else 1))
            real_maxdata = max(real_maxdata, dsize & 0x7FFFFFFF)
    if real_maxsub > st_maxsub:
        problems["max subkey name len too small"] += 1; examples["max subkey name len too small"].append(f"{path} stored {st_maxsub} real {real_maxsub}")
    if real_maxval > st_maxval:
        problems["max value name len too small"] += 1; examples["max value name len too small"].append(f"{path} stored {st_maxval} real {real_maxval}")
    if real_maxdata > st_maxdata:
        problems["max value data len too small"] += 1; examples["max value data len too small"].append(f"{path} stored {st_maxdata} real {real_maxdata}")
print(sys.argv[1], "keys:", seen)
for k, n in problems.items():
    print(f"  {k}: {n}")
    for e in examples[k][:4]:
        print("     ", e)
