#!/usr/bin/env python3
"""Prototype: build a restore plan for files missing from an installed \\Windows,
and emit a guestfish script that applies it.

Only *missing* files are handled here (no overwrites yet).

Usage:
  plan.py WIM_LISTING VM_SHA1 VM_SOFTWARE_HIVE --stage DIR --out PREFIX
"""
import argparse
import collections
import json
import os

import hivex

from filediff import EMPTY_SHA1, ATTR_DIRECTORY, ATTR_REPARSE, excluded, parse_vm

# Files Windows moves after install: WIM path -> where it ends up (volume-relative).
KNOWN_MOVES = {
    "system32/recovery/winre.wim": "Recovery/WindowsRE/Winre.wim",
}


def parse_wim_full(path):
    """Return {lower relpath: entry}, entry = dict(rel, hash, attrs, sd, link)."""
    out = {}
    cur = None
    in_unnamed = False

    def flush():
        if cur and cur["path"].startswith("/Windows/"):
            rel = cur["path"][len("/Windows/"):]
            cur["rel"] = rel
            out[rel.lower()] = cur

    with open(path, encoding="utf-8", errors="surrogateescape") as f:
        for line in f:
            if line.startswith("Full Path"):
                flush()
                cur = {"path": line.split("=", 1)[1].strip().strip('"'), "hash": None,
                       "attrs": 0, "sd": None, "link": None}
                in_unnamed = False
            elif cur is None:
                continue
            elif line.startswith("Attributes"):
                cur["attrs"] = int(line.split("=", 1)[1], 16)
            elif line.startswith("Security Descriptor"):
                cur["sd"] = line.split("=", 1)[1].strip()
            elif line.startswith("Link Group ID"):
                cur["link"] = line.split("=", 1)[1].strip()
            elif line.startswith("Link Count") and int(line.split("=", 1)[1]) < 2:
                cur["link"] = None
            elif "Unnamed data stream" in line:
                in_unnamed = True
            elif "data stream" in line:
                in_unnamed = False
            elif in_unnamed and line.startswith("Hash"):
                cur["hash"] = line.split("=", 1)[1].strip()[2:]
                in_unnamed = False
    flush()
    for e in out.values():
        if not e["attrs"] & ATTR_DIRECTORY and not e["hash"]:
            e["hash"] = EMPTY_SHA1
    return out


def cbs_packages(hive_path):
    h = hivex.Hivex(hive_path)
    n = h.root()
    for part in r"Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages".split("\\"):
        n = h.node_get_child(n, part)
    return {h.node_name(c).lower() for c in h.node_children(n)}


def installed_components(hive_path):
    """WinSxS component dirs (lowercase) that have at least one owner (c! value)
    in the COMPONENTS hive. Components without owner are staged, not installed."""
    h = hivex.Hivex(hive_path)
    comps = h.node_get_child(h.node_get_child(h.root(), "DerivedData"), "Components")
    out = set()
    for c in h.node_children(comps):
        if any(h.value_key(v).startswith("c!") for v in h.node_values(c)):
            out.add(h.node_name(c).lower())
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("wim_listing")
    ap.add_argument("vm_sha1")
    ap.add_argument("vm_software")
    ap.add_argument("vm_components")
    ap.add_argument("--vm-volume-files", help="optional sha1 list of whole volume (for moves)")
    ap.add_argument("--vm-dirs", help="find0 output of /Windows (NUL-separated dirs+files)")
    ap.add_argument("--stage", required=True, help="host dir with files extracted from WIM")
    ap.add_argument("--out", default="plan")
    a = ap.parse_args()

    wim = parse_wim_full(a.wim_listing)
    vm = parse_vm(a.vm_sha1)
    pkgs = cbs_packages(a.vm_software)
    owned = installed_components(a.vm_components)
    vm_sxs_dirs = {k.split("/")[1] for k in vm if k.startswith("winsxs/") and k.count("/") >= 2}

    groups = collections.defaultdict(list)
    for k, e in wim.items():
        if e["link"] and not e["attrs"] & ATTR_DIRECTORY:
            groups[e["link"]].append(k)

    actions = []          # (kind, rel, extra)
    skipped = collections.Counter()
    for k, e in sorted(wim.items()):
        if e["attrs"] & ATTR_DIRECTORY or k in vm or excluded(k):
            continue
        if e["attrs"] & ATTR_REPARSE:
            skipped["reparse point (not handled yet)"] += 1
            continue
        if k in KNOWN_MOVES:
            skipped["known move"] += 1
            continue
        parts = k.split("/")
        if parts[0] == "winsxs" and len(parts) >= 3 and parts[1] not in vm_sxs_dirs:
            skipped["WinSxS component removed"] += 1
            continue
        if parts[0] == "servicing" and parts[1] == "packages":
            pkg = os.path.splitext(parts[2])[0]
            if pkg not in pkgs:
                skipped["CBS package not installed"] += 1
                continue
        siblings = [s for s in groups.get(e["link"], []) if s != k]
        sxs = [s.split("/")[1] for s in siblings if s.startswith("winsxs/")]
        if sxs and not any(c in owned for c in sxs):
            skipped["component not installed (no owner in COMPONENTS)"] += 1
            continue
        present = [s for s in siblings if s in vm and vm[s][1] == e["hash"]]
        if present:
            actions.append(("link", e["rel"], wim[present[0]]["rel"]))
            continue
        if any(s.startswith("winsxs/") for s in siblings):
            skipped["WinSxS twin also missing (component removed)"] += 1
            continue
        actions.append(("extract", e["rel"], None))

    # Directories that have to be created, parents first.
    need_dirs = set()
    vm_dirs = {os.path.dirname(k) for k in vm}
    vm_dirs |= {"/".join(d.split("/")[:i]) for d in list(vm_dirs) for i in range(1, d.count("/") + 1)}
    for _, rel, _ in actions:
        d = os.path.dirname(rel)
        while d and d.lower() not in vm_dirs:
            need_dirs.add(d)
            d = os.path.dirname(d)

    # Directories from the WIM that are gone, even if empty (e.g. System32\GroupPolicy).
    if a.vm_dirs:
        names = open(a.vm_dirs, "rb").read().split(b"\0")
        present = {n.decode("utf-8", "surrogateescape").lstrip("./").lower() for n in names if n}
        for k, e in wim.items():
            if not e["attrs"] & ATTR_DIRECTORY or k in present or excluded(k + "/"):
                continue
            parts = k.split("/")
            if parts[0] == "winsxs" and len(parts) >= 2 and parts[1] not in vm_sxs_dirs:
                skipped["dir of removed WinSxS component"] += 1
                continue
            need_dirs.add(e["rel"])

    print(f"restore actions: {len(actions)}")
    print(f"  link    : {sum(1 for x in actions if x[0] == 'link')}")
    print(f"  extract : {sum(1 for x in actions if x[0] == 'extract')}")
    print(f"  mkdir   : {len(need_dirs)}")
    print("skipped:")
    for r, n in skipped.most_common():
        print(f"  {n:6d}  {r}")

    with open(f"{a.out}.json", "w") as f:
        json.dump({"actions": actions, "mkdir": sorted(need_dirs), "skipped": skipped}, f, indent=1)
    with open(f"{a.out}.extract.txt", "w") as f:
        for kind, rel, _ in actions:
            if kind == "extract":
                f.write(f"/Windows/{rel}\n")

    # Apply script, run inside the libguestfs appliance (volume mounted at /sysroot
    # with ntfs-3g). Idempotent: existing targets are left alone.
    import shlex
    root = "/sysroot/Windows/"
    stage = "/sysroot/Windows/Temp/winrebase-stage/"

    def setsd(rel):
        return f"setfattr -h -n system.ntfs_acl -v 0x{wim[rel.lower()]['sd']} {shlex.quote(root + rel)}"

    lines = ["set -u", "fail=0"]
    for d in sorted(need_dirs, key=lambda x: x.count("/")):
        lines.append(f"[ -d {shlex.quote(root + d)} ] || {{ mkdir {shlex.quote(root + d)} && {setsd(d)}; }} || fail=1")
    for kind, rel, src in actions:
        dst = shlex.quote(root + rel)
        if kind == "link":
            lines.append(f"[ -e {dst} ] || ln {shlex.quote(root + src)} {dst} || fail=1")
        else:
            lines.append(f"[ -e {dst} ] || {{ cp {shlex.quote(stage + rel)} {dst} && {setsd(rel)}; }} || fail=1")
    lines.append('echo "apply done, fail=$fail"')
    with open(f"{a.out}.apply.sh", "w") as f:
        f.write("\n".join(lines) + "\n")
    lines = lines[2:]
    print(f"wrote {a.out}.json, {a.out}.extract.txt, {a.out}.apply.sh ({len(lines)} commands)")


if __name__ == "__main__":
    main()
