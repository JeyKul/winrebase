#!/usr/bin/env python3
"""Prototype: find registry keys/values that exist in a WIM hive but are missing
(or different) in the installed hive.

Usage: regdiff.py WIM_HIVE VM_HIVE [--out PREFIX] [--depth N]
"""
import argparse
import collections

import hivex

REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ = 1, 2, 7
# WIM hives use X: as placeholder for the system drive; Setup rewrites it.
WIM_DRIVE = "X:".encode("utf-16-le")
WIM_DRIVE_LOWER = "x:".encode("utf-16-le")


def fix_drive(t, data, drive):
    if t in (REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ):
        target = drive.encode("utf-16-le")
        return data.replace(WIM_DRIVE, target).replace(WIM_DRIVE_LOWER, target)
    return data


def current_controlset(h):
    """Return 'ControlSet00N' for a SYSTEM hive, or None for other hives."""
    sel = h.node_get_child(h.root(), "Select")
    if not sel:
        return None
    for v in h.node_values(sel):
        if h.value_key(v) == "Current":
            return "ControlSet%03d" % h.value_dword(v)
    return None


def children(h, node):
    return {h.node_name(c).lower(): c for c in h.node_children(node)}


def values(h, node):
    out = {}
    for v in h.node_values(node):
        t, data = h.value_value(v)
        out[h.value_key(v).lower()] = (h.value_key(v), t, data)
    return out


DRIVE = "C:"


def walk(wh, wn, vh, vn, path, res):
    """wn exists in WIM; vn is the matching VM node (exists)."""
    wv = values(wh, wn)
    try:
        vv = values(vh, vn)
        vc = children(vh, vn)
    except RuntimeError as e:
        res["corrupt"].append((path, str(e)))
        return
    for k, (name, t, data) in wv.items():
        if k not in vv:
            res["missing_value"].append((path, name))
        elif vv[k][1:] != (t, fix_drive(t, data, DRIVE)):
            res["changed_value"].append((path, name))
    for k, wc in children(wh, wn).items():
        sub = path + "\\" + wh.node_name(wc)
        if k in vc:
            walk(wh, wc, vh, vc[k], sub, res)
        else:
            res["missing_key"].append((sub, count_subtree(wh, wc)))


def count_subtree(h, node):
    return 1 + sum(count_subtree(h, c) for c in h.node_children(node))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("wim")
    ap.add_argument("vm")
    ap.add_argument("--out", default="regdiff")
    ap.add_argument("--depth", type=int, default=4, help="path depth for grouping")
    a = ap.parse_args()

    wh, vh = hivex.Hivex(a.wim), hivex.Hivex(a.vm)
    res = {"missing_key": [], "missing_value": [], "changed_value": [], "corrupt": []}

    wcs, vcs = current_controlset(wh), current_controlset(vh)
    if wcs:
        # SYSTEM: compare only the current control set, mapped across both sides,
        # plus the non-ControlSet top-level keys.
        print(f"control sets: wim={wcs} vm={vcs}")
        wroot, vroot = wh.root(), vh.root()
        walk(wh, wh.node_get_child(wroot, wcs), vh, vh.node_get_child(vroot, vcs),
             "CurrentControlSet", res)
        vtop = children(vh, vroot)
        for k, wc in children(wh, wroot).items():
            if k.startswith("controlset"):
                continue
            name = wh.node_name(wc)
            if k in vtop:
                walk(wh, wc, vh, vtop[k], name, res)
            else:
                res["missing_key"].append((name, count_subtree(wh, wc)))
    else:
        walk(wh, wh.root(), vh, vh.root(), "", res)

    def group(p):
        return "\\".join(p.strip("\\").split("\\")[:a.depth])

    for kind, items in res.items():
        total = sum(n for _, n in items) if kind == "missing_key" else len(items)
        print(f"{kind}: {len(items)} entries ({total} keys incl. subkeys)" if kind == "missing_key"
              else f"{kind}: {len(items)}")
        for g, n in collections.Counter(group(p) for p, _ in items).most_common(15):
            print(f"    {n:7d}  {g}")
        with open(f"{a.out}.{kind}.txt", "w", encoding="utf-8", errors="replace") as f:
            for p, x in sorted(items):
                f.write(f"{p}\t{x}\n")


if __name__ == "__main__":
    main()
