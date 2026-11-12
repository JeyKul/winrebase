#!/usr/bin/env python3
"""Prototype: replay Windows registry transaction logs (.LOG1/.LOG2, new format, Win 8.1+)
into a copy of the primary hive.

Format reference: Maxim Suhanov, "Windows registry file format specification".

Usage: hivelog.py HIVE OUT [--log1 HIVE.LOG1] [--log2 HIVE.LOG2]
"""
import argparse
import struct
import sys

BASE_BLOCK = 4096
PAGE = 512
M32 = 0xFFFFFFFF
MARVIN_SEED = 0x82EF4D887A4E55C5


def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & M32


def marvin32(data, seed=MARVIN_SEED):
    lo, hi = seed & M32, seed >> 32

    def block(lo, hi):
        hi ^= lo
        lo = _rotl(lo, 20)
        lo = (lo + hi) & M32
        hi = _rotl(hi, 9)
        hi ^= lo
        lo = _rotl(lo, 27)
        lo = (lo + hi) & M32
        hi = _rotl(hi, 19)
        return lo, hi

    n = len(data) // 4 * 4
    for i in range(0, n, 4):
        lo = (lo + struct.unpack_from("<I", data, i)[0]) & M32
        lo, hi = block(lo, hi)
    final = int.from_bytes(bytes(data[n:]) + b"\x80", "little")
    lo = (lo + final) & M32
    lo, hi = block(lo, hi)
    lo, hi = block(lo, hi)
    return (hi << 32) | lo


def checksum(base):
    x = 0
    for i in range(0, 508, 4):
        x ^= struct.unpack_from("<I", base, i)[0]
    if x == M32:
        x = 0xFFFFFFFE
    elif x == 0:
        x = 1
    return x


def parse_log(path):
    """Return (base_block_seq, [entries]); entry = dict(seq, bins_size, pages=[(off, bytes)])."""
    try:
        d = open(path, "rb").read()
    except FileNotFoundError:
        return None
    if len(d) < PAGE or d[:4] != b"regf":
        return None
    hdr_seq1, hdr_seq2 = struct.unpack_from("<II", d, 4)
    entries = []
    pos = PAGE
    while pos + 40 <= len(d) and d[pos:pos + 4] == b"HvLE":
        size, flags, seq, bins_size, count = struct.unpack_from("<IIIII", d, pos + 4)
        h1, h2 = struct.unpack_from("<QQ", d, pos + 24)
        if size < 40 or size % PAGE or pos + size > len(d):
            break
        entry = d[pos:pos + size]
        if marvin32(entry[40:]) != h1 or marvin32(entry[:32]) != h2:
            break
        refs = [struct.unpack_from("<II", entry, 40 + 8 * i) for i in range(count)]
        dpos = 40 + 8 * count
        pages = []
        for off, sz in refs:
            pages.append((off, entry[dpos:dpos + sz]))
            dpos += sz
        entries.append({"seq": seq, "bins_size": bins_size, "pages": pages})
        pos += size
    return {"seq1": hdr_seq1, "seq2": hdr_seq2, "entries": entries}


def replay(hive_path, out_path, log_paths, verbose=True):
    hive = bytearray(open(hive_path, "rb").read())
    base = hive[:PAGE]
    if base[:4] != b"regf":
        sys.exit("not a hive")
    seq1, seq2 = struct.unpack_from("<II", base, 4)
    if verbose:
        print(f"primary: seq1={seq1} seq2={seq2} {'clean' if seq1 == seq2 else 'dirty'}")

    logs = [l for l in (parse_log(p) for p in log_paths) if l and l["entries"]]
    # Apply logs in order of their first entry's sequence number.
    logs.sort(key=lambda l: l["entries"][0]["seq"])

    expected = None
    applied = 0
    last = None
    for log in logs:
        for e in log["entries"]:
            if e["seq"] < seq2:
                continue            # already in the primary file
            if expected is not None and e["seq"] != expected:
                if verbose:
                    print(f"  gap: expected seq {expected}, got {e['seq']} -> stop this log")
                break
            need = BASE_BLOCK + e["bins_size"]
            if len(hive) < need:
                hive.extend(b"\0" * (need - len(hive)))
            for off, data in e["pages"]:
                p = BASE_BLOCK + off
                hive[p:p + len(data)] = data
            applied += 1
            last = e
            expected = e["seq"] + 1
    if verbose:
        print(f"applied {applied} log entries"
              + (f", last seq {last['seq']}" if last else ""))
    if last:
        new_seq = last["seq"] + 1
        struct.pack_into("<II", hive, 4, new_seq, new_seq)
        struct.pack_into("<I", hive, 0x28, last["bins_size"])
        del hive[BASE_BLOCK + last["bins_size"]:]
    elif seq1 != seq2:
        struct.pack_into("<II", hive, 4, seq1, seq1)
    struct.pack_into("<I", hive, 0x1FC, checksum(hive))
    open(out_path, "wb").write(hive)
    return applied


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("hive")
    ap.add_argument("out")
    ap.add_argument("--log1")
    ap.add_argument("--log2")
    a = ap.parse_args()
    replay(a.hive, a.out, [a.log1 or a.hive + ".LOG1", a.log2 or a.hive + ".LOG2"])


if __name__ == "__main__":
    main()
