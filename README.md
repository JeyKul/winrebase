# winrebase

Repair a corrupted Windows install **in place** by rebasing it onto a clean WIM of the
**exact same build**, without a reinstall and without losing users, apps, drivers or data.

> **Status:** working prototype. The WinPE app (`app/`) repairs files and registry hives
> offline and brought a blind-broken Windows 11 VM back several times (deleted System32,
> deleted SOFTWARE/SYSTEM keys, torn hives). Not tested on real hardware yet.
> Findings: [docs/FINDINGS.md](docs/FINDINGS.md).

## The problem

Sometimes Windows breaks in ways the built-in tools don't fix. Example that started this
project: DWM kept crashing, and the cause turned out to be **missing registry keys**.

- `sfc /scannow` and `DISM /RestoreHealth` only check **files**, not the registry.
- An in-place upgrade (`setup.exe` → "keep files and apps") is slow, needs a working OS
  to start from, and is a black box.
- A clean reinstall loses everything.

## The idea

Boot offline (WinPE or Linux), then compare the broken install against a clean WIM of the
same build:

| Item | In WIM and install | Only in install | Only in WIM |
|------|--------------------|-----------------|-------------|
| Files in `\Windows` | replace with WIM version | **keep** (runtimes, drivers, app DLLs) | restore |
| Registry keys | keep the install's value (optional: reset) | **keep** (users, apps, hardware) | **add** |
| Pending updates | discard | — | — |

User data, `Program Files`, profiles and anything third-party stay where they are.

## ⚠️ Warning

This tool rewrites system files and registry hives on purpose.

- **Make a full disk backup first.** The tool requires you to confirm that a backup exists.
- **The WIM must match the installed build exactly** (build + UBR, e.g. `26100.4652`). The
  tool reads the build from the offline hive and refuses a mismatched WIM. Matching ISOs
  can be built with [UUP dump](https://uupdump.net).
- You use it at your own risk. See [LICENSE](LICENSE).

## Targets

- **WinPE** (primary): bootable USB, native Windows APIs.
- **Linux** (secondary): bootable live USB, `ntfs-3g` + `hivex`.

Both share one core. See [docs/DESIGN.md](docs/DESIGN.md#architecture).

## Build the WinPE ISO

Needs Rust with the `x86_64-pc-windows-gnu` target, MinGW, `wimlib-imagex`, `7z`, `xorriso`.

```sh
tools/build-wimlib.sh                       # static wimlib for MinGW (once)
(cd app && cargo build --release)           # app/target/x86_64-pc-windows-gnu/release/winrebase.exe
tools/build-iso.sh Win11_25H2_German_x64.iso   # -> build/winrebase-pe.iso
```

The ISO boots WinPE (from that Windows ISO's `boot.wim`) straight into winrebase. It
contains Microsoft files: build it yourself, don't redistribute it.

## Using it

1. Boot the PC from the winrebase ISO/USB. Have the matching Windows ISO or
   `install.wim`/`.esd` on a disk/USB, or attached as second drive.
2. **Search** finds Windows installations and images (also inside `.iso` files, which are
   mounted read-only). **Browse** takes a `.wim`, `.esd` or `.iso`.
3. **Analyze**: compares every file under `\Windows` with the image and checks all
   registry hives (log replay, missing keys vs. the image's hives, device state).
4. **Repair**: restores files, rewrites damaged hives (originals in
   `\Windows\winrebase-backup\<time>\config`), checks boot files.

What the registry stage repairs: torn hives (log replay, never across a sequence gap),
deleted keys (recovered from free cells, else added from the image), lost servicing/AppX
databases, the hardware profile, device driver keys, user profile entries, the computer
name, per-user app registrations and app capability entries (CapAuthz). Details:
[docs/FINDINGS.md](docs/FINDINGS.md).

**Clean device start** (checkbox, automatic when the device part of SYSTEM is damaged):
device state comes from the image, Windows detects all hardware again on first boot
("Getting devices ready"), like after a fresh install. Users, apps and drive letters stay.

## Docs

- [docs/DESIGN.md](docs/DESIGN.md) — how it works, rules, architecture
- [docs/RISKS.md](docs/RISKS.md) — known problems and open questions
- [docs/TESTING.md](docs/TESTING.md) — how to break Windows on purpose and test the fix
- [docs/ROADMAP.md](docs/ROADMAP.md) — milestones

## License

GPL-3.0-or-later.
