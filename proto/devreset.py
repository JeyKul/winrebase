#!/usr/bin/env python3
"""Clean device start: replace a SYSTEM hive's PnP device state with the WIM's.

Windows then detects all hardware again on first boot, like a fresh install (the WIM
image is generalized and boots on any hardware). Users, apps, services config, drive
letters (MountedDevices) and everything else stay.

Replaced from the WIM: <CS>\\Enum, <CS>\\Control\\DeviceClasses, <CS>\\Control\\DeviceContainers,
the instance keys under <CS>\\Control\\Class\\{guid}\\NNNN, and the Start value of every
service that is boot-start (0) in the WIM.

Usage: devreset.py WIM_SYSTEM VM_SYSTEM OUT
"""
import sys

from hivecompact import load_tree, write_tree
from regrepair2 import get


def current(root):
    for n, t, d in get(root, "Select")["values"]:
        if n.lower() == "current":
            return "ControlSet%03d" % int.from_bytes(d[:4], "little")


def reset_devices(wim, vm, log):
    wcs, vcs = get(wim, current(wim)), get(vm, current(vm))
    wc, vc = get(wcs, "Control"), get(vcs, "Control")
    vcs["subs"]["enum"] = get(wcs, "Enum")
    for name in ("deviceclasses", "devicecontainers"):
        if name in wc["subs"]:
            vc["subs"][name] = wc["subs"][name]
        else:
            vc["subs"].pop(name, None)
    wclass, vclass = get(wc, "Class"), get(vc, "Class")
    for low, k in vclass["subs"].items():
        w = wclass["subs"].get(low)
        for inst in [i for i in k["subs"] if i.isdigit()]:
            del k["subs"][inst]
        if w is not None:
            for inst, ik in w["subs"].items():
                if inst.isdigit():
                    k["subs"][inst] = ik
    n = 0
    for low, ws in get(wcs, "Services")["subs"].items():
        start = [v for v in ws["values"] if v[0].lower() == "start"]
        vs = get(vcs, "Services")["subs"].get(low)
        if not start or vs is None or int.from_bytes(start[0][2][:4], "little") != 0:
            continue
        vs["values"] = [v for v in vs["values"] if v[0].lower() != "start"] + [start[0]]
        n += 1
    log.append(f"device state reset from WIM, {n} boot-start services")
    return n


if __name__ == "__main__":
    wim, _ = load_tree(sys.argv[1])
    vm, base = load_tree(sys.argv[2])
    log = []
    reset_devices(wim, vm, log)
    print("\n".join(log))
    print(write_tree(vm, base, sys.argv[3]))
