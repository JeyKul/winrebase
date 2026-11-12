# Testing

No broken PC needed. Break a VM on purpose, repair it, check it, repeat.

No snapshots: real customer PCs arrive already broken, without a backup. The tool has to
work from that state, and its own rollback set is the only safety net.

## Setup

- libvirt VM `win11-2`: UEFI Secure Boot (OVMF), hardware TPM passthrough, qcow2 disk.
- Install ISO: `Win11_25H2_German_x64.iso` → `install.wim`, build **26200.6584**, 10 editions.
- Clean WIM = the install ISO as long as the VM stays at 26200.6584. Once the VM updates,
  build a matching ISO (UUP dump) for the new UBR.
- Disk access from the host while the VM is **shut off**: `guestfish --ro -d win11-2`
  (read-only), or `guestmount` for `find`/`stat`.
- **Try repairs on a qcow2 overlay, never on the disk itself**:
  `qemu-img create -f qcow2 -b /var/lib/libvirt/images/win11-2.qcow2 -F qcow2 ov.qcow2`,
  patch the overlay with `guestfish -a ov.qcow2`, boot it as a transient domain
  (`virsh create`, copy of the win11-2 XML without TPM/network, own NVRAM copy). Each try
  starts from a fresh overlay; the real disk stays broken until the fix is proven.
  Bisecting a bad hive this way (graft subtrees from the repaired hive into a known-good
  one, one boot each) found the IDConfigDB and DeviceClasses rules.
- Host-side registry test: `app/regtool` runs the WinPE app's registry code on Linux
  (`cargo build --release --target x86_64-unknown-linux-gnu`, then
  `regtool HIVE OUT --wim WIM_HIVE --log HIVE.LOG1 --log HIVE.LOG2`).
- Test the tool from both:
  - a WinPE ISO attached as CD
  - a Linux live ISO attached as CD

## Reset between tests

No snapshot, so if a repair fails:

1. Boot it if possible → run `setup.exe` from the ISO → "keep files and apps"
   (manual in-place upgrade).
2. If it doesn't boot anymore: reinstall from the ISO.

That's also the baseline the tool is compared against: it should fix what an in-place
upgrade fixes, faster, offline, and on PCs that don't boot.

Note: with TPM passthrough, Windows 11 may turn on device encryption (BitLocker) by itself.
Check `manage-bde -status`, and keep the recovery key. Offline access needs it.

## Breakage scenarios

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
