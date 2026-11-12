# winrebase

Repair a corrupted Windows install **in place** by rebasing it onto a clean WIM of the
**exact same build**, without a reinstall and without losing users, apps, drivers or data.

> **Status:** design phase. Nothing here is runnable yet. See [docs/DESIGN.md](docs/DESIGN.md).

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

## Docs

- [docs/DESIGN.md](docs/DESIGN.md) — how it works, rules, architecture
- [docs/RISKS.md](docs/RISKS.md) — known problems and open questions
- [docs/TESTING.md](docs/TESTING.md) — how to break Windows on purpose and test the fix
- [docs/ROADMAP.md](docs/ROADMAP.md) — milestones

## License

GPL-3.0-or-later.
