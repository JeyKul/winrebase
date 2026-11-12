#!/usr/bin/env python3
"""Prototype: add registry keys/values that exist in the WIM hive but are missing in the
installed hive. Existing values are never changed (only reported).

Input VM hive must be clean (run hivelog.py first).

Usage: regrepair.py WIM_HIVE VM_HIVE OUT_HIVE [--report FILE]
"""
import argparse

import hivex

from hiveundelete import FreeCells
from regdiff import (children, current_controlset, fix_drive, fix_name, is_state, values,
                     DRIVE)


# hivex writes big values as one plain cell; bigdata.py converts them to db records
MAX_PLAIN_VALUE = 1 << 30   # big values are fixed up afterwards by bigdata.py


def set_value(vh, vn, name, t, data, path, log):
    if len(data) > MAX_PLAIN_VALUE:
        log.append(("skipped big value", path, name))
        return
    vh.node_set_value(vn, {"key": name, "t": t, "value": data})
    log.append(("value", path, name))


def undelete(vh, src_hive, log):
    """Re-create keys that were deleted but still sit intact in free cells of the same
    hive (parents first). Only keys that don't exist any more are touched."""
    deleted = FreeCells(src_hive).deleted_keys()
    for low in sorted(deleted, key=lambda k: k.count("\\")):
        path, vals, _ = deleted[low]
        parts = path.strip("\\").split("\\")
        node = vh.root()
        for part in parts[:-1]:
            node = vh.node_get_child(node, part)
            if not node:
                break
        if not node or vh.node_get_child(node, parts[-1]):
            continue
        vn = vh.node_add_child(node, parts[-1])
        log.append(("undeleted key", path, None))
        for name, t, data in vals:
            set_value(vh, vn, name, t, data, path, log)


def copy_values(wh, wn, vh, vn, path, log, only_missing):
    have = values(vh, vn) if only_missing else {}
    for k, (name, t, data) in values(wh, wn, fixnames=True).items():
        if is_state(path, k) or k in have:
            continue
        set_value(vh, vn, fix_name(name), t, fix_drive(t, data, DRIVE), path, log)


def copy_subtree(wh, wn, vh, vparent, name, path, log):
    vn = vh.node_add_child(vparent, name)
    log.append(("key", path, None))
    copy_values(wh, wn, vh, vn, path, log, only_missing=False)
    for wc in wh.node_children(wn):
        cname = wh.node_name(wc)
        sub = path + "\\" + cname
        if not is_state(sub):
            copy_subtree(wh, wc, vh, vn, cname, sub, log)


def merge(wh, wn, vh, vn, path, log, changed):
    if is_state(path):
        return
    copy_values(wh, wn, vh, vn, path, log, only_missing=True)
    vv = values(vh, vn)
    for k, (name, t, data) in values(wh, wn, fixnames=True).items():
        if not is_state(path, k) and k in vv and vv[k][1:] != (t, fix_drive(t, data, DRIVE)):
            changed.append((path, name))
    vc = children(vh, vn)
    for k, wc in children(wh, wn).items():
        cname = wh.node_name(wc)
        sub = path + "\\" + cname
        if k in vc:
            merge(wh, wc, vh, vc[k], sub, log, changed)
        elif not is_state(sub):
            copy_subtree(wh, wc, vh, vn, cname, sub, log)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("wim")
    ap.add_argument("vm")
    ap.add_argument("out")
    ap.add_argument("--report", default=None)
    ap.add_argument("--no-undelete", action="store_true")
    a = ap.parse_args()

    wh = hivex.Hivex(a.wim)
    vh = hivex.Hivex(a.vm, write=True)
    log, changed = [], []
    if not a.no_undelete:
        undelete(vh, a.vm, log)
        print(f"undeleted keys from free cells: {sum(1 for x in log if x[0] == 'undeleted key')}")

    wcs, vcs = current_controlset(wh), current_controlset(vh)
    if wcs:
        wroot, vroot = wh.root(), vh.root()
        merge(wh, wh.node_get_child(wroot, wcs), vh, vh.node_get_child(vroot, vcs),
              "CurrentControlSet", log, changed)
        vtop = children(vh, vroot)
        for k, wc in children(wh, wroot).items():
            if k.startswith("controlset"):
                continue
            name = wh.node_name(wc)
            if k in vtop:
                merge(wh, wc, vh, vtop[k], name, log, changed)
            elif not is_state(name):
                copy_subtree(wh, wc, vh, vroot, name, name, log)
    else:
        merge(wh, wh.root(), vh, vh.root(), "", log, changed)

    for x in log:
        if x[0] == "skipped big value":
            print(f"  ! skipped value > {MAX_PLAIN_VALUE} bytes: {x[1]} : {x[2]}")
    keys = [x for x in log if x[0] == "key"]
    vals = [x for x in log if x[0] == "value"]
    print(f"added keys: {len(keys)}, added values (incl. in new keys): {len(vals)}, "
          f"changed values (kept): {len(changed)}")
    top = [x for x in log if x[0] == "key" and not any(
        x[1].startswith(y[1] + "\\") for y in keys if y is not x)]
    for _, p, _ in top[:50]:
        print(f"  + {p}")
    for _, p, n in vals:
        if not any(p == y[1] for y in keys):
            print(f"  + {p} : {n}")
    if a.report:
        with open(a.report, "w", encoding="utf-8") as f:
            for kind, p, n in log:
                f.write(f"add {kind}\t{p}\t{n or ''}\n")
            for p, n in changed:
                f.write(f"changed (kept)\t{p}\t{n}\n")
    if log:
        vh.commit(a.out)
        import bigdata
        n = bigdata.fix(a.out)
        if n:
            print(f"converted {n} big value(s) to db records")
    else:
        print("nothing to do")


if __name__ == "__main__":
    main()
