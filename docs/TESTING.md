# Testing

No broken PC needed. Break a VM on purpose, repair it, check it, roll back, repeat.

## Setup

- KVM/QEMU (virt-manager) with UEFI (OVMF) + TPM (swtpm) for Windows 11.
- Install Windows from a UUP dump ISO of a known build.
- Let it update to a known UBR, then build a second ISO of that exact UBR → the "clean WIM".
- Snapshot the VM: `clean`.
- Test the tool from both:
  - a WinPE ISO attached as CD
  - a Linux live ISO attached as CD

## Breakage scenarios

Each scenario starts from the `clean` snapshot.

| # | Scenario | How to break it | Expected after repair |
|---|----------|-----------------|-----------------------|
| 1 | Missing DWM registry keys (the original case) | delete keys under `SOFTWARE\Microsoft\Windows\Dwm` and related `CLSID`s | DWM works, keys restored |
| 2 | Corrupt system DLL | overwrite e.g. `dwmcore.dll` with random bytes (offline) | file restored, boots normally |
| 3 | Deleted system file | delete a file from `System32` (offline) | file restored |
| 4 | Broken service config | delete a service key under `SYSTEM\CurrentControlSet\Services` | service key restored |
| 5 | Stuck pending update | start an update, cut power during "Working on updates" | pending state cleared, boots |
| 6 | Wrong ACLs | take ownership of `System32\drivers` and reset ACLs | ACLs back to TrustedInstaller |
| 7 | Third-party stuff survives | install VC++ redist, .NET, a GPU driver, an app, a second user | all still present and working |
| 8 | Build mismatch | use a WIM of a different UBR | tool refuses, clear message |
| 9 | BitLocker | enable BitLocker | tool asks to unlock, works after |
| 10 | Fast Startup | shut down with Fast Startup on | tool refuses or discards hibernation |

## What "working" means

- Boots to desktop, user can log in, all users still exist.
- Scenario-specific check passes.
- `sfc /scannow` and `DISM /Online /Cleanup-Image /ScanHealth` report no problems.
- Windows Update still installs the next CU.
- Apps from scenario 7 still start.
- Activation still active.

## Automation (later)

- `virsh snapshot-revert` + `qemu-nbd` / `guestfish` to break the image from the host.
- Boot the repair ISO with a kernel cmdline / `startnet.cmd` that runs the tool unattended.
- Boot Windows, run a check script via `virsh qemu-agent-command` or a scheduled task that
  writes results to a shared folder.
