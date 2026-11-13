#!/usr/bin/env python3
"""Prototype: "pour the WIM back over \\Windows" for massive damage.

Unlike plan.py this does not trust the WinSxS folders or the COMPONENTS hive (both may
be gone). Everything the WIM has under \\Windows and the volume lacks is restored, except:
  - excluded live-state paths (filediff.EXCLUDE_*)
  - known moves (Winre.wim)
  - servicing\\Packages entries the SOFTWARE hive's CBS database doesn't list
Files whose hardlink twin still exists on the volume are re-linked (keeps the
System32 <-> WinSxS structure); the rest is extracted with wimextract, which keeps hardlink
groups, and copied in as a tar.

Outputs (prefix --out):
  .extract.txt   wimextract path list
  .apply.sh      runs in the libguestfs appliance after the tar is unpacked:
                 hardlinks to surviving twins + security descriptors
  .casemap.json  WIM dir -> existing VM dir casing (applied to the staged tree)

Usage: fullrestore.py WIM_LISTING VM_SHA1 VM_FIND0 SOFTWARE_HIVE [extra /Windows paths...] --out P
"""
import argparse
import collections
import json
import os
import shlex

from filediff import excluded, parse_vm
from plan import KNOWN_MOVES, cbs_packages, parse_wim_full

ATTR_DIRECTORY = 0x10
ATTR_REPARSE = 0x400


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("wim_listing")
    ap.add_argument("vm_sha1")
    ap.add_argument("vm_find0")
    ap.add_argument("software")
    ap.add_argument("extra", nargs="*", help="extra WIM paths under /Windows to restore "
                    "even if excluded (e.g. missing hives)")
    ap.add_argument("--replace", action="store_true",
                    help="also replace files whose content differs from the WIM (another "
                    "build was poured over \\Windows)")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    wim = parse_wim_full(a.wim_listing)
    vm = parse_vm(a.vm_sha1)
    names = [n.decode("utf-8", "surrogateescape").lstrip("./")
             for n in open(a.vm_find0, "rb").read().split(b"\0") if n]
    vm_paths = {n.lower(): n for n in names}            # dirs + files, real casing
    pkgs = cbs_packages(a.software)
    extra = {p.lower().removeprefix("/windows/") for p in a.extra}

    groups = collections.defaultdict(list)
    for k, e in wim.items():
        if e["link"] and not e["attrs"] & ATTR_DIRECTORY:
            groups[e["link"]].append(k)

    restore, links, replaced, skipped = [], [], [], collections.Counter()
    for k, e in sorted(wim.items()):
        if e["attrs"] & ATTR_DIRECTORY:
            continue
        if k in vm_paths and not (a.replace and k in vm and vm[k][1] != e["hash"]):
            continue
        if excluded(k) and k not in extra:
            skipped["excluded"] += 1
            continue
        if k in KNOWN_MOVES:
            skipped["known move"] += 1
            continue
        if e["attrs"] & ATTR_REPARSE:
            skipped["reparse point"] += 1
            continue
        parts = k.split("/")
        if parts[0] == "servicing" and parts[1] == "packages" and \
                os.path.splitext(parts[2])[0] not in pkgs:
            skipped["CBS package not installed"] += 1
            continue
        if k in vm_paths:
            replaced.append(vm_paths[k])
        twin = [s for s in groups.get(e["link"], []) if s != k and s in vm
                and vm[s][1] == e["hash"]]
        if twin:
            links.append((vm_paths[twin[0]], e["rel"]))
        else:
            restore.append(e["rel"])

    # directories that will exist: missing WIM dirs get created (by tar or mkdir)
    missing_dirs = sorted({e["rel"] for k, e in wim.items()
                           if e["attrs"] & ATTR_DIRECTORY and k not in vm_paths
                           and not excluded(k + "/")}, key=lambda p: p.count("/"))

    # case map: WIM dir path -> existing VM path where only the casing differs
    casemap = {}
    for k, e in wim.items():
        if e["attrs"] & ATTR_DIRECTORY and k in vm_paths and vm_paths[k] != e["rel"]:
            casemap[e["rel"]] = vm_paths[k]

    print(f"replace (content differs): {len(replaced)}")
    print(f"extract: {len(restore)}  relink to surviving twin: {len(links)}  "
          f"new dirs: {len(missing_dirs)}  case fixes: {len(casemap)}")
    for r, n in skipped.most_common():
        print(f"  skipped {n:6d} {r}")

    with open(a.out + ".extract.txt", "w") as f:
        for r in restore:
            f.write(f"/Windows/{r}\n")
    with open(a.out + ".casemap.json", "w") as f:
        json.dump(casemap, f, indent=1)

    def real(rel):
        """Path with existing VM casing for its parent directories."""
        parts = rel.split("/")
        for i in range(len(parts), 0, -1):
            pre = "/".join(parts[:i])
            if pre in casemap:
                return casemap[pre] + ("/" + "/".join(parts[i:]) if parts[i:] else "")
        return rel

    root = "/sysroot/Windows/"

    def setsd(rel):
        sd = wim[rel.lower()]["sd"]
        return f"setfattr -h -n system.ntfs_acl -v 0x{sd} {shlex.quote(root + real(rel))}"

    lines = ["fail=0"]
    with open(a.out + ".replace.txt", "w") as f:
        for r in replaced:
            f.write(f"/Windows/{r}\n")
    for d in missing_dirs:
        lines.append(f"mkdir -p {shlex.quote(root + real(d))} && {setsd(d)} || fail=$((fail+1))")
    for src, dst in links:
        lines.append(f"ln -f {shlex.quote(root + src)} {shlex.quote(root + real(dst))} "
                     f"|| fail=$((fail+1))")
    seen_groups = set()
    for r in restore:
        g = wim[r.lower()]["link"]
        if g and g in seen_groups:
            continue                     # hardlinks share one security descriptor
        if g:
            seen_groups.add(g)
        lines.append(f"{setsd(r)} || fail=$((fail+1))")
    lines.append('echo "apply done, failures: $fail"')
    with open(a.out + ".apply.sh", "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {a.out}.extract.txt, {a.out}.apply.sh ({len(lines)} lines), {a.out}.casemap.json")


if __name__ == "__main__":
    main()
