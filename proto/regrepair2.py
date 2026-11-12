#!/usr/bin/env python3
"""Prototype v2: repair a registry hive in memory and write it compactly.

Order:
  1. (caller) replay transaction logs with hivelog.py
  2. undelete intact keys from free cells (with class names + security descriptors)
  3. restore lost state databases from the WIM (SOFTWARE)
  4. add keys/values missing compared to the WIM (X: -> C:)
  5. write a fresh compact hive (hivecompact.write_tree)

Usage: regrepair2.py WIM_HIVE VM_HIVE OUT [--vm-files SHA1LIST] [--report FILE]
"""
import argparse
import re

from hivecompact import load_tree, write_tree
from hiveundelete import FreeCells, classes_from_logs
from regdiff import fix_drive, fix_name, is_state, DRIVE

STATE_LOSS = 0.5
RESTORABLE_STATE = (
    r"\microsoft\windows\currentversion\sidebyside",
    r"\microsoft\windows\currentversion\component based servicing",
    r"\microsoft\windows\currentversion\appx\appxalluserstore",
    r"\microsoft\windows\currentversion\capabilityaccessmanager\capabilities",
)
CBS_PACKAGES = r"\microsoft\windows\currentversion\component based servicing\packages"


def new_key(name, like):
    """Empty key with metadata (sd, class, flags...) taken from `like`."""
    return {"name": name, "flags": like["flags"] & ~0x2C, "ts": like["ts"],
            "access": like["access"], "class": like["class"], "sd": like["sd"],
            "values": [], "subs": {}, "restored": True}


def count(k):
    return 1 + sum(count(c) for c in k["subs"].values())


def get(k, path):
    for part in [p for p in path.split("\\") if p]:
        k = k["subs"].get(part.lower())
        if k is None:
            return None
    return k


class Repair:
    def __init__(self, vm, wim, log):
        self.vm, self.wim, self.log = vm, wim, log
        self.cs_map = {}
        if get(wim, "Select") is not None:
            def current(root):
                for n, t, d in get(root, "Select")["values"]:
                    if n.lower() == "current":
                        return "ControlSet%03d" % int.from_bytes(d[:4], "little")
            self.cs_map = {current(vm): current(wim)}

    # -- 2. undelete ------------------------------------------------------------
    def undelete(self, deleted):
        """Windows clears the security pointer of deleted keys, so the descriptor comes
        from the same key in the WIM, or else from the parent (what inheritance gives)."""
        for low in sorted(deleted, key=lambda k: k.count("\\")):
            path, vals, _, (cls, sd, flags, access, ts) = deleted[low]
            parts = [p for p in path.split("\\") if p]
            parent = get(self.vm, "\\".join(parts[:-1]))
            if parent is None:
                continue
            existing = parent["subs"].get(parts[-1].lower())
            if existing is not None:
                if existing.get("from_wim"):
                    # created from the WIM in this run: the machine's own copy wins
                    existing["values"] = list(vals) + [
                        v for v in existing["values"]
                        if v[0].lower() not in {x[0].lower() for x in vals}]
                    if cls:
                        existing["class"] = cls
                    existing["from_wim"] = False
                    self.log.append(("undeleted over wim", path, "class" if cls else ""))
                continue
            if sd is None:
                wk = get(self.wim, self.wim_path(path))
                sd = wk["sd"] if wk else parent["sd"]
            parent["subs"][parts[-1].lower()] = {
                "name": parts[-1], "flags": flags & ~0x2C, "ts": ts, "access": access,
                "class": cls, "sd": sd, "values": list(vals), "subs": {}, "restored": True}
            self.log.append(("undeleted", path, "class" if cls else ""))

    def wim_path(self, path):
        """VM path -> WIM path (control set numbers may differ)."""
        if self.cs_map:
            low = path.lower().lstrip("\\")
            for vcs, wcs in self.cs_map.items():
                if low.startswith(vcs.lower()):
                    return wcs + path.lstrip("\\")[len(vcs):]
        return path

    # -- 3. lost state databases ---------------------------------------------------
    def restore_lost_state(self, installed_mums):
        for sk in RESTORABLE_STATE:
            w = get(self.wim, sk)
            if w is None:
                continue
            v = get(self.vm, sk)
            if v is not None and count(v) > count(w) * (1 - STATE_LOSS):
                continue
            print(f"state area lost ({count(v) if v else 0}/{count(w)} keys): {sk}")
            if v is None:
                parts = [p for p in sk.split("\\") if p]
                parent = get(self.vm, "\\".join(parts[:-1]))
                if parent is None:
                    continue
                v = parent["subs"][parts[-1].lower()] = new_key(w["name"], w)
                self.log.append(("key", sk, ""))
            self.copy_into(w, v, sk, state_ok=True, installed_mums=installed_mums)

    # -- 4. WIM merge -------------------------------------------------------------
    def copy_values(self, w, v, path, state_ok=False):
        have = {fix_name(n).lower() for n, _, _ in v["values"]}
        for name, t, data in w["values"]:
            n = fix_name(name)
            if n.lower() in have or (not state_ok and is_state(path, n)):
                continue
            v["values"].append((n, t, fix_drive(t, data, DRIVE)))
            self.log.append(("value", path, n))

    def copy_into(self, w, v, path, state_ok=False, installed_mums=None):
        """Add everything from WIM key w missing in VM key v (recursive)."""
        if not state_ok and is_state(path):
            return
        self.copy_values(w, v, path, state_ok)
        for low, wc in w["subs"].items():
            sub = path + "\\" + wc["name"]
            if (path.lower() == CBS_PACKAGES and installed_mums is not None
                    and low not in installed_mums):
                self.log.append(("skipped removed package", sub, ""))
                continue
            if not state_ok and is_state(sub):
                continue
            vc = v["subs"].get(low)
            if vc is None:
                vc = v["subs"][low] = new_key(wc["name"], wc)
                vc["from_wim"] = True
                self.log.append(("key", sub, ""))
            self.copy_into(wc, vc, sub, state_ok, installed_mums)

    def merge(self):
        sel = get(self.wim, "Select")
        if sel is not None:            # SYSTEM: map the current control set on both sides
            def current(root):
                for n, t, d in get(root, "Select")["values"]:
                    if n.lower() == "current":
                        return "ControlSet%03d" % int.from_bytes(d[:4], "little")
            wcs, vcs = current(self.wim), current(self.vm)
            self.copy_into(get(self.wim, wcs), get(self.vm, vcs), "CurrentControlSet")
            for low, wc in self.wim["subs"].items():
                if low.startswith("controlset"):
                    continue
                vc = self.vm["subs"].get(low)
                if vc is None:
                    if is_state(wc["name"]):
                        continue
                    vc = self.vm["subs"][low] = new_key(wc["name"], wc)
                    self.log.append(("key", wc["name"], ""))
                self.copy_into(wc, vc, wc["name"])
        else:
            self.copy_into(self.wim, self.vm, "")


def prune_interfaces(vm, rep, log):
    r"""Control\DeviceClasses\{guid}\##?#<device>#{guid} must have its reference-string
    subkey(s) "#..." (where the symbolic link lives). Keys that came back half (undelete,
    deleted children) stop the kernel with IO1_INITIALIZATION_FAILED (0x69). Dropped ones
    are re-created by PnP when the device starts."""
    cs = get(vm, list(rep.cs_map)[0])
    dc = get(cs, r"Control\DeviceClasses")
    n = 0
    if dc is None:
        return 0
    for g in dc["subs"].values():
        for low, inst in list(g["subs"].items()):
            if low.startswith("##?#") and not any(c.startswith("#") for c in inst["subs"]):
                del g["subs"][low]
                log.append(("incomplete interface dropped", r"Control\DeviceClasses\%s\%s" % (g["name"], inst["name"]), ""))
                n += 1
    return n


def fix_hwprofile(vm, rep, log):
    """The WIM's Control\\IDConfigDB is the pre-setup template (CurrentConfig 0, only the
    "Pristine" profile 0000). Setup clones it into profile 0001+ and points CurrentConfig
    there; with the template the boot loader stops with 0xc0000001. Rebuild it from the
    profiles the machine still has under <ControlSet>\\Hardware Profiles."""
    import uuid
    cs = get(vm, list(rep.cs_map)[0])
    idc = get(cs, r"Control\IDConfigDB")
    profiles = get(cs, "Hardware Profiles")
    if idc is None or profiles is None:
        return 0
    vals = {v[0].lower(): v for v in idc["values"]}
    cur = int.from_bytes(vals["currentconfig"][2][:4], "little") if "currentconfig" in vals else 0
    nums = [int(n) for n in profiles["subs"] if n.isdigit() and int(n) > 0]
    hp = idc["subs"].get("hardware profiles")
    if cur and hp is not None and "%04d" % cur in hp["subs"]:
        return 0                                    # intact
    if not nums:
        return 0
    n = max(nums)
    dword = lambda x: x.to_bytes(4, "little")
    sz = lambda s: (s + "\0").encode("utf-16-le")

    def setv(k, name, t, data):
        k["values"] = [v for v in k["values"] if v[0].lower() != name.lower()] + [(name, t, data)]

    if hp is None:
        hp = idc["subs"]["hardware profiles"] = new_key("Hardware Profiles", idc)
    setv(hp, "Undocked", 4, dword(n))
    p = hp["subs"].get("%04d" % n)
    if p is None:
        p = hp["subs"]["%04d" % n] = new_key("%04d" % n, hp)
    for name, t, data in [("PreferenceOrder", 4, dword(0)), ("FriendlyName", 1, sz("Undocked Profile")),
                          ("Aliasable", 4, dword(0)), ("Cloned", 4, dword(1)),
                          ("HwProfileGuid", 1, sz("{%s}" % uuid.uuid4()))]:
        if name.lower() not in {v[0].lower() for v in p["values"]}:
            setv(p, name, t, data)
    alias = idc["subs"].get("acpialias")
    if alias is None:
        alias = idc["subs"]["acpialias"] = new_key("AcpiAlias", idc)
        a = alias["subs"]["0001"] = new_key("0001", alias)
        a["values"] = [("DockingState", 4, dword(1)), ("AcpiSerialNumber", 3, b"\0\0"),
                       ("ProfileNumber", 4, dword(n))]
    setv(idc, "CurrentConfig", 4, dword(n))
    log.append(("hardware profile", r"Control\IDConfigDB", "%04d" % n))
    return n


CONFIGFLAG_REINSTALL = 0x20


DRIVER_PROPS = "{a8b865dd-2e3d-4094-ad97-e593a70c75d6}"   # DEVPKEY_Driver* property set
# property id -> value name in the Control\Class\{guid}\NNNN driver key
DRIVER_KEY_VALUES = [("0004", "DriverDesc"), ("0009", "ProviderName"), ("0002", "DriverDateData"),
                     ("0002", "DriverDate"), ("0003", "DriverVersion"), ("0005", "InfPath"),
                     ("0006", "InfSection"), ("0008", "MatchingDeviceId")]


REINSTALL_CLASSES = {"{4d36e972-e325-11ce-bfc1-08002be10318}"}   # Net


def driver_key_from_props(props):
    r"""Values of a device's driver key, rebuilt from Enum\...\Properties\{a8b865dd...}.
    PnP keeps a copy of the driver data there, so it survives when Control\Class is lost.
    Returns None when the essential properties are missing."""
    import datetime
    if props is None:
        return None
    raw = {}
    for pid, k in props["subs"].items():
        for n, t, d in k["values"]:
            if n == "":
                raw[pid.upper()] = (t & 0xFFFF, d)
    if "0005" not in raw or "0004" not in raw:
        return None
    out = []
    for pid, name in DRIVER_KEY_VALUES:
        if pid not in raw:
            continue
        t, d = raw[pid]
        if name == "DriverDateData":
            out.append((name, 3, d[:8]))
        elif name == "DriverDate":
            ft = int.from_bytes(d[:8], "little")
            day = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
            out.append((name, 1, f"{day.month}-{day.day}-{day.year}\0".encode("utf-16-le")))
        else:
            out.append((name, 1, d))
    return out


def service_start(cs, name):
    k = get(cs, "Services\\" + name) if name else None
    if k is None:
        return None
    for n, t, d in k["values"]:
        if n.lower() == "start":
            return int.from_bytes(d[:4], "little")
    return None


def fix_devices(vm, rep, log):
    r"""Devices whose Control\Class\{guid}\NNNN driver key is gone.

    1. Rebuild the driver key from the device's own driver properties (Enum\...\Properties).
       That's enough for the kernel to start the device normally.
    2. CONFIGFLAG_REINSTALL, so PnP re-runs the INF, only when the key couldn't be rebuilt
       or the class keeps more in it than the properties hold (network: NetCfgInstanceId,
       Ndi keys).
    Never reinstall a boot/system-start device: PnP can't install it before the boot disk
    is up, and the kernel stops with IO1_INITIALIZATION_FAILED / INACCESSIBLE_BOOT_DEVICE."""
    cs = get(vm, list(rep.cs_map)[0])
    classes = get(cs, "Control\\Class")
    rebuilt = flagged = 0

    def walk(k, path, depth):
        nonlocal rebuilt, flagged
        if depth == 3:
            vals = {v[0].lower(): v for v in k["values"]}
            if "driver" not in vals:
                return
            drv = vals["driver"][2].decode("utf-16-le", "replace").rstrip("\0")
            guid, _, inst = drv.partition("\\")
            c = classes["subs"].get(guid.lower()) if classes else None
            if c is not None and inst.lower() in c["subs"]:
                return
            svc = vals["service"][2].decode("utf-16-le", "replace").rstrip("\0") if "service" in vals else ""
            start = service_start(cs, svc)
            dk = driver_key_from_props(k["subs"].get("properties", {"subs": {}})["subs"].get(DRIVER_PROPS.lower()))
            if dk is not None and c is not None:
                nk = c["subs"][inst.lower()] = new_key(inst, c)
                nk["values"] = dk
                log.append(("driver key from properties", path, drv))
                rebuilt += 1
            if start is not None and start <= 1:
                return
            if dk is not None and guid.lower() not in REINSTALL_CLASSES:
                return
            old = int.from_bytes(vals["configflags"][2][:4], "little") if "configflags" in vals else 0
            k["values"] = [v for v in k["values"] if v[0].lower() != "configflags"] + [
                ("ConfigFlags", 4, (old | CONFIGFLAG_REINSTALL).to_bytes(4, "little"))]
            log.append(("pnp reinstall", path, drv))
            flagged += 1
            return
        for c in k["subs"].values():
            walk(c, path + "\\" + c["name"], depth + 1)
    walk(get(cs, "Enum"), "Enum", 0)
    return rebuilt, flagged


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("wim")
    ap.add_argument("vm")
    ap.add_argument("out")
    ap.add_argument("--vm-files", help="sha1 list of \\Windows (installed CBS .mum files)")
    ap.add_argument("--report")
    ap.add_argument("--logs", nargs="*", default=[],
                    help="original .LOG1/.LOG2 (old key records -> class names)")
    a = ap.parse_args()

    vm, base = load_tree(a.vm)
    wim, _ = load_tree(a.wim)
    log = []
    rep = Repair(vm, wim, log)

    fc = FreeCells(a.vm)
    deleted = fc.deleted_keys()
    rep.undelete(deleted)
    print(f"undeleted: {sum(1 for x in log if x[0] == 'undeleted')} keys "
          f"({sum(1 for x in log if x[0] == 'undeleted' and x[2])} with class names)")
    if get(wim, "Select") is None:
        mums = None
        if a.vm_files:
            mums = set()
            for line in open(a.vm_files, encoding="utf-8", errors="surrogateescape"):
                m = re.search(r"\./servicing/Packages/(.+)\.mum$", line.rstrip("\n"), re.I)
                if m:
                    mums.add(m.group(1).lower())
        rep.restore_lost_state(mums)
    rep.merge()
    before = sum(1 for x in log if x[0] == "undeleted")
    rep.undelete(deleted)       # 2nd pass: parents that only came back from the WIM
    print(f"undeleted after WIM merge: {sum(1 for x in log if x[0] == 'undeleted') - before}")
    print(f"from WIM: {sum(1 for x in log if x[0] == 'key')} keys, "
          f"{sum(1 for x in log if x[0] == 'value')} values")
    # devices whose driver key is gone: let PnP reinstall them on next boot
    if get(wim, "Select") is not None:
        n = prune_interfaces(vm, rep, log)
        if n:
            print(f"incomplete device interfaces dropped: {n}")
        n = fix_hwprofile(vm, rep, log)
        if n:
            print(f"hardware profile rebuilt: CurrentConfig = {n}")
        r, f = fix_devices(vm, rep, log)
        if r or f:
            print(f"devices: {r} driver keys rebuilt from properties, {f} marked for PnP reinstall")

    # class names for restored keys that came back without one (e.g. Lsa boot key)
    for path, cls in classes_from_logs(fc, a.logs).items():
        k = get(vm, path)
        if k is not None and k.get("restored") and k["class"] != cls:
            k["class"] = cls
            log.append(("class from log", path, cls.decode("utf-16-le", "replace")))
            print(f"class name from log: {path} = {cls.decode('utf-16-le', 'replace')}")
    n, s = write_tree(vm, base, a.out)
    print(f"wrote {n} keys, {s} security descriptors")
    if a.report:
        with open(a.report, "w", encoding="utf-8") as f:
            for kind, p, x in log:
                f.write(f"{kind}\t{p}\t{x}\n")


if __name__ == "__main__":
    main()
