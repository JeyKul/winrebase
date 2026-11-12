#!/usr/bin/env python3
"""Prototype: compare \\Windows of a WIM image against an installed Windows.

Inputs:
  wim listing  -> `wimlib-imagex dir WIM INDEX --path=/Windows --detailed`
  vm hashes    -> `guestfish ... checksums-out sha1 /Windows OUT` (paths relative to \\Windows)

Output: summary on stdout, full lists as TSV next to --out.
"""
import argparse
import collections
import re

EMPTY_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
ATTR_DIRECTORY = 0x10
ATTR_REPARSE = 0x400

# Paths (relative to \Windows, lowercase) the tool never touches. See docs/DESIGN.md.
EXCLUDE_PREFIXES = (
    "system32/config/",
    "system32/catroot2/",
    "system32/logfiles/",
    "logs/",
    "panther/",
    "temp/",
    "prefetch/",
    "softwaredistribution/",
    "serviceprofiles/",
)
EXCLUDE_SUFFIXES = (".log", ".etl")


def parse_wim(path):
    """Return {lowercase relpath: (relpath, sha1, attrs)} for non-directory entries."""
    files = {}
    cur = None
    in_unnamed = False

    def flush():
        if cur and not cur["attrs"] & ATTR_DIRECTORY:
            rel = cur["path"][len("/Windows/"):]
            files[rel.lower()] = (rel, cur["hash"] or EMPTY_SHA1, cur["attrs"])

    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        for line in f:
            if line.startswith("Full Path"):
                flush()
                p = line.split("=", 1)[1].strip().strip('"')
                cur = {"path": p, "hash": None, "attrs": 0}
                in_unnamed = False
            elif cur is None:
                continue
            elif line.startswith("Attributes"):
                cur["attrs"] = int(line.split("=", 1)[1], 16)
            elif "Unnamed data stream" in line:
                in_unnamed = True
            elif "data stream" in line:
                in_unnamed = False
            elif in_unnamed and line.startswith("Hash"):
                cur["hash"] = line.split("=", 1)[1].strip()[2:]
                in_unnamed = False
    flush()
    files.pop("", None)
    return files


def parse_vm(path):
    files = {}
    rx = re.compile(r"^([0-9a-f]{40})\s+\./(.*)$")
    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        for line in f:
            m = rx.match(line.rstrip("\n"))
            if m:
                files[m.group(2).lower()] = (m.group(2), m.group(1))
    return files


def excluded(key):
    return key.startswith(EXCLUDE_PREFIXES) or key.endswith(EXCLUDE_SUFFIXES)


def bucket(key):
    parts = key.split("/")
    return "/".join(parts[:2]) if parts[0] in ("system32", "syswow64", "winsxs") else parts[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("wim")
    ap.add_argument("vm")
    ap.add_argument("--out", default="filediff")
    a = ap.parse_args()

    wim = parse_wim(a.wim)
    vm = parse_vm(a.vm)

    result = {"replace": [], "restore": [], "keep_extra": [], "excluded": [], "same": 0,
              "reparse_skipped": []}
    for key, (rel, sha, attrs) in wim.items():
        if excluded(key):
            result["excluded"].append(rel)
        elif attrs & ATTR_REPARSE:
            result["reparse_skipped"].append(rel)
        elif key not in vm:
            result["restore"].append(rel)
        elif vm[key][1] != sha:
            result["replace"].append(rel)
        else:
            result["same"] += 1
    for key, (rel, _) in vm.items():
        if key not in wim and not excluded(key):
            result["keep_extra"].append(rel)

    print(f"WIM files: {len(wim)}   VM files: {len(vm)}")
    print(f"same: {result['same']}")
    for k in ("replace", "restore", "keep_extra", "excluded", "reparse_skipped"):
        lst = result[k]
        print(f"{k}: {len(lst)}")
        top = collections.Counter(bucket(p.lower()) for p in lst).most_common(12)
        for b, n in top:
            print(f"    {n:7d}  {b}")
        with open(f"{a.out}.{k}.txt", "w") as f:
            f.write("\n".join(sorted(lst)) + "\n")


if __name__ == "__main__":
    main()
