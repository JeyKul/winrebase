# Design

## Goal

Take a broken Windows install and make every **Windows-owned** file and registry key match a
clean image of the same build, while keeping everything the user or third parties added.

Non-goals:

- Repairing user data, apps in `Program Files`, or third-party drivers.
- Upgrading or downgrading Windows. Same build in, same build out.
- Running on a live, booted Windows. Everything happens offline.

## Pipeline

```
 0. Preflight      backup confirmation, BitLocker check, find the Windows volume
 1. Identify       read build + UBR + edition from offline SOFTWARE hive
 2. Match WIM      pick the image index whose build/edition matches; refuse otherwise
 3. Snapshot       copy hives + a manifest of everything we will touch → rollback set
 4. Diff           files and registry, WIM vs install → plan (dry-run report)
 5. Clean pending  discard pending updates and reboot operations
 6. Apply files    replace/restore according to the plan
 7. Apply registry merge according to the plan
 8. Verify         re-diff, write a report, leave the rollback set on disk
```

Steps 0–4 are read-only. Default mode stops after step 4 and prints the plan
(`--dry-run`). Writing needs `--apply` plus the backup confirmation.

## Step details

### 0. Preflight

- Require an explicit "I have a backup" confirmation (flag or prompt).
- BitLocker: the volume has to be unlocked (WinPE: `manage-bde -unlock`; Linux: `dislocker`).
  Fail clearly if it's locked.
- Hibernation / Fast Startup: if `hiberfil.sys` holds a hibernated session, the volume is
  dirty. Refuse, unless `--discard-hibernation` is passed (Linux: `ntfs-3g` refuses to mount
  it read-write anyway).
- Find the Windows volume: look for `Windows\System32\config\SYSTEM`. If there's more than
  one, ask.

### 1. Identify

From `SOFTWARE\Microsoft\Windows NT\CurrentVersion`:

- `CurrentBuild`, `UBR` → full build (`26100.4652`)
- `EditionID`, `InstallationType`
- architecture from `SYSTEM\...\Session Manager\Environment\PROCESSOR_ARCHITECTURE`

### 2. Match WIM

- Read every image in the WIM/ESD (`wimlib` gives the XML metadata per index).
- Read the build from the **image's own SOFTWARE hive**. The XML metadata can be stale.
- Exact build + UBR + edition match → continue. Anything else → stop and tell the user which
  build to get (UUP dump link format in the error message).

### 3. Snapshot (rollback set)

Written to `<WindowsVolume>\winrebase\<timestamp>\` (or an external drive with `--backup-dir`):

- all hives: `System32\config\{SYSTEM,SOFTWARE,SAM,SECURITY,DEFAULT,COMPONENTS,DRIVERS}`
  and every `NTUSER.DAT` / `UsrClass.dat`
- every file that will be replaced, including its security descriptor
- `plan.json` (the diff) and `undo.json` (how to reverse each step)

This doesn't replace the full backup. It makes a quick undo possible.

### 4. Diff

#### Files

Scope: `\Windows`. Everything else is out of scope.

| Case | Action |
|------|--------|
| In both, same hash | nothing |
| In both, hash differs | replace with WIM version |
| Only in WIM | restore |
| Only in install | **keep** |

Never touched (excluded paths):

- `Windows\System32\config\*` (handled by the registry step)
- `Windows\System32\catroot2`, `Windows\Logs`, `Windows\Panther`, `Windows\Temp`
- `Windows\SoftwareDistribution` (only cleaned by step 5)
- `Windows\System32\DriverStore\FileRepository` entries not present in the WIM
- `Windows\Prefetch`, `Windows\ServiceProfiles`, `Windows\System32\LogFiles`
- `*.log`, `*.etl`, page/swap/hiberfil
- anything listed in a user exclusion file (`--exclude`)

Comparison is by content hash (SHA-1, which the WIM already stores per stream), not by
timestamp.

NTFS metadata that has to be preserved:

- **Security descriptors** (TrustedInstaller ownership). Take them from the WIM.
- **Hardlinks** between `WinSxS` and `System32`. Re-link instead of copying, or disk usage
  doubles and servicing gets confused.
- **Reparse points** (e.g. `WOF` compressed files, app execution aliases).
- Alternate data streams, if the WIM has them.
- Short (8.3) names, if the WIM has them.

#### Registry

Hives compared: `SYSTEM`, `SOFTWARE`, `DEFAULT`, `Users\Default\NTUSER.DAT`
(the default profile hive is compared against each user's `NTUSER.DAT` too, adding only
missing keys).

`SAM` and `SECURITY` are **never** touched (user accounts, secrets, machine identity).

| Case | Default action | With `--reset-values` |
|------|----------------|-----------------------|
| Key/value in WIM, missing in install | **add** | add |
| In both, different data | keep install | overwrite with WIM |
| Only in install | keep | keep |

Ignored subtrees (always machine/user specific):

- `SYSTEM\MountedDevices`, `SYSTEM\*\Enum`, `SYSTEM\*\Control\Class\*\0000…` instance keys
- `SYSTEM\Select`, `ControlSet` numbering: map `CurrentControlSet` on both sides via `Select\Current`
- `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
- `SOFTWARE\Microsoft\Cryptography\MachineGuid`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages` (servicing state — must stay consistent with WinSxS, both are same build anyway)
- anything in the user exclusion file

Security descriptors on keys are copied from the WIM when a key is added.

### 5. Clean pending

Same as `DISM /Image:X:\ /Cleanup-Image /RevertPendingActions`, plus:

- delete `Windows\WinSxS\pending.xml` (keep a copy in the rollback set)
- empty `Windows\SoftwareDistribution\Download`
- remove `PendingFileRenameOperations` / `PendingFileRenameOperations2` from
  `SYSTEM\CurrentControlSet\Control\Session Manager`
- remove `RebootPending` / `PackagesPending` under
  `SOFTWARE\...\Component Based Servicing`
- remove `SOFTWARE\...\WindowsUpdate\Auto Update\RebootRequired`

### 6–7. Apply

- Files: written from the WIM streams. Order: restore missing, then replace differing.
  Hardlinks re-created after all streams are written.
- Registry: hive edits on offline copies, then swap them in atomically (rename), old ones kept
  in the rollback set.

### 8. Verify

- Re-run the diff, expect zero file differences in scope and zero missing keys.
- Write `report.html` / `report.txt`.
- Next boot: suggest `DISM /Online /Cleanup-Image /ScanHealth` and `sfc /scannow` as a
  second opinion.

## Architecture

One core, two backends.

```
             ┌──────────────────────────┐
             │ core (Rust)              │
             │  plan / diff / rules     │
             │  report, rollback        │
             └──────┬──────────┬────────┘
                    │ traits   │
        ┌───────────┴──┐   ┌───┴────────────┐
        │ WinPE backend│   │ Linux backend  │
        │ Win32 + NTFS │   │ ntfs-3g        │
        │ offreg.dll   │   │ hivex          │
        │ wimlib (dll) │   │ wimlib (.so)   │
        └──────────────┘   └────────────────┘
```

Why Rust: one static-ish binary per target, no runtime to ship into WinPE (WinPE has no
Python), good FFI to `wimlib` / `hivex` / Win32.

Core traits (sketch):

- `ImageSource` — list files, read streams + security descriptors from the WIM (`wimlib`
  on both targets)
- `TargetVolume` — read/write files with full NTFS metadata (Win32 `BackupRead/BackupWrite`
  on WinPE; `ntfs-3g` on Linux, or `wimlib`'s NTFS-3G apply mode)
- `HiveStore` — load/edit/save offline hives (`offreg.dll` on WinPE; `hivex` on Linux)

Read-only hive parsing could also be done in pure Rust (`nt-hive` crate) for the diff, so
the diff engine is identical on both targets and only writes go through the backend.

### Deliverables

- `winrebase.exe` + a script that injects it into a WinPE image (`copype` + `DISM /Add-Package`)
- `winrebase` Linux binary + a small live-ISO recipe (Arch/archiso)
- later: a simple TUI/GUI wrapper around the same CLI

## Possible later extension: manifest-based registry check

`WinSxS\Manifests\*.manifest` describes the registry keys every component writes, for the exact
installed version. Decoding them (DCM delta compression, see `wcp.dll`) would allow a check
**without any WIM**, and would also cover keys from cumulative updates. Not part of v1.
