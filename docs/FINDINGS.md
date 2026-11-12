# Findings

Log of what we learned from real data.

## 2026-11-12 — Baseline: healthy VM vs its own WIM

Setup: VM `win11-2`, Windows 11 Pro for Workstations 26200.6584 (de-DE), freshly installed,
not broken. WIM: `Win11_25H2_German_x64.iso` index 9, same build.

Tools: `wimlib-imagex dir --detailed` (WIM already stores SHA-1 per stream, no extraction),
`guestfish checksums-out sha1` on the VM disk (read-only), `hivex` for hives.
Prototype scripts: `proto/filediff.py`, `proto/regdiff.py`.

**Speed:** full `\Windows` hash + diff in ~15 s (WIM listing 2 s). Very cheap.

### Files (`\Windows`)

| | count |
|-|-------|
| WIM files | 121 401 |
| identical | 121 053 |
| differ | 22 |
| only in WIM | 286 |
| only in VM | 669 |

- **All 22 "differ" are live state files** Windows rewrites itself: WMI repository
  (`System32\wbem\Repository`), perf counters (`perf[ch]0xx.dat`), `System32\SMI\Store`
  (a hive), `WinSxS\FileMaps\*.cdf-ms`, `WinSxS\migration.xml`, `servicing\Sessions`,
  `Setup\State\State.ini`, `System32\Recovery\ReAgent.xml`. → add to exclusions.
- **"Only in WIM" ≠ missing.** All 286 were removed by Windows on purpose:
  - WMIC feature-on-demand (removed in 25H2) → files + `servicing\Packages\*WMIC*`
  - one `WinSxS\amd64_userexperience-aix_*` component (217 files)
  - `System32\Recovery\Winre.wim` → moved to `\Recovery\WindowsRE\Winre.wim` by ReAgent
  → restore decisions must check CBS package state (installed / staged / absent)
  and known moves, not just presence.
- **Only in VM** (kept anyway): scheduled tasks, event logs, INF/driver store additions,
  rescache, spool. As expected.

### Registry

Missing in VM (key or value present in WIM, absent in VM):

| hive | missing keys | missing values |
|------|--------------|----------------|
| SYSTEM | 1 | 12 |
| SOFTWARE | 234 (669 incl. subkeys) | 158 |
| DEFAULT | 0 | 0 |
| Default `NTUSER.DAT` | 0 | 0 |

SOFTWARE missing keys are mostly Task Scheduler cache (`Schedule`), `Appx` (removed
provisioned apps), `Component Based Servicing` (the removed WMIC packages), `Print`.
→ same story as files: intentional removals, need CBS/Appx awareness.

**WIM hives use `X:` as the system drive placeholder.** Setup rewrites every `X:\...`
string to `C:\...`. Without normalising, SOFTWARE showed 17 931 "changed" values; with
`X:` → `C:` mapping it's 1 036 (SYSTEM: 304 → 129). **When adding values from the WIM the
tool must rewrite `X:` too**, or it writes broken paths.

The WIM `DEFAULT` hive is only 32 KiB. Setup builds the real one, so it's a weak reference.

### Open from this run

- Hive transaction logs (`.LOG1/.LOG2`) are not replayed by `hivex`. After an unclean
  shutdown the base hive can be stale. Need log replay (Windows does it on `RegLoadKey`;
  on Linux: own implementation or `regipy`/`libregf`).
- `COMPONENTS` hive not diffed yet.

Next: break the VM on purpose (scenarios 1–4) and check the breakage stands out from
this baseline.

## 2026-11-12 — First blind repair: "boots, never reaches desktop"

The user broke the VM without telling what they did. Symptom: boots, never reaches the
desktop, an empty error dialog.

### Diagnosis (read-only, ~1 min)

- **573 files deleted** from `System32` / `SysWOW64` (beyond the baseline):
  `Microsoft-Edge-WebView` (169), `SysWOW64\wbem` (67), 32-bit PowerShell modules,
  `Keywords`, ~50 `SysWOW64\<lang>` folders, `vulkan-1.dll`, `opencl.dll`, `msclmd.dll`,
  perf counters, `OEMDefaultAssociations.*`, … and all of `System32\Tasks`.
- No file content changed, only deletions.
- Registry base hives: no new missing keys. **SOFTWARE was dirty** (seq 824/823). Log
  replay with `regipy` produced 12 unreadable nodes and a wrong header checksum → not
  trustworthy. Need our own replay (or WinPE, where Windows replays natively).
- `System32\Tasks` contents aren't in the WIM (setup generates them), can't restore from WIM.

### Restore rules that worked (`proto/plan.py`)

No baseline needed: a healthy VM gets **0 actions**, the broken VM gets **exactly the 573
deleted files**, nothing else.

1. WinSxS file, whole component folder gone → removed on purpose, skip.
2. `servicing\Packages\X.mum/.cat`, package key `X` gone from CBS → skip.
3. Known moves (`System32\Recovery\Winre.wim` → `\Recovery\WindowsRE\`) → skip.
4. File has hardlink twins in WinSxS: the component (= WinSxS folder name = key under
   `COMPONENTS\DerivedData\Components`) must have an owner (`c!…` value). No owner →
   staged, not installed (e.g. WMIC in 25H2) → skip.
5. Twin present on disk → **re-create the hardlink** (content + ACL come with it).
6. No twin → extract from WIM, set ACL from the WIM security descriptor.

Gotcha: `wimlib-imagex dir --detailed` gives unlinked files a dummy link group; only
`Link Count > 1` means a real hardlink.

Result: 531 hardlinks, 42 extracted files, 107 folders (with ACLs).

### Applying from Linux

- Mount with **ntfs-3g** (not the kernel `ntfs3` driver) to get `system.ntfs_acl`
  (full self-relative security descriptor) via `setfattr`.
- The volume was **dirty** (NTFS journal not replayed, Windows was cut off). ntfs-3g
  falls back to read-only silently. Used `ntfsfix -d` (empties the journal, risky, user's
  choice). → WinPE is the safer target: Windows replays `$LogFile` itself.
- `guestfish debug sh` doesn't keep quoting → upload a real shell script into the guest
  and run it in the appliance (`proto/plan.py` emits `plan.apply.sh`, idempotent).
- Applying 573 files: ~1 s.

Verified: missing-file list identical to the healthy baseline, hardlink counts restored,
ACLs equal to WIM.

## 2026-11-12 — After file repair: still no desktop

Boot after restoring the 573 files: services start, then no desktop.

- Event realtime buffers (`System32\LogFiles\WMI\RtBackup\EtwRTEventLog-*.etl`) are the only
  logs written when the system never settles; `.evtx` weren't flushed.
  - SCM: `gpsvc` (0xC0000002), `CoreMessagingRegistrar`, `TimeBrokerSvc`, `AppIDSvc`,
    `BDESVC`, `NcbService`, `DsmSvc` fail with error 31.
  - Hard error popup = **`dwm.exe - Systemfehler`** (the "empty error message").
  - Application log: ~169k events in 3 min, loop around AppContainer profile of
    `microsoft.windows.fontdrvhost` (`profext\appcontainer.cpp` line 1863).
- Hives still dirty after the boot (Windows replays logs in memory, never flushed).
- **Own log replay `proto/hivelog.py`** (HvLE entries, Marvin32 checks): works, hivex
  opens the result, 0 corrupt nodes (regipy's output had 12). → registry identical to the
  healthy baseline. The user didn't touch the registry.
- Whole-volume diff (Program Files, ProgramData, Users) vs WIM: nothing relevant missing
  (WindowsApps deprovisioned by Windows, ClipSVC install stubs consumed at first boot).

### What the WIM can't restore

The deletions also hit machine-generated files, which no WIM contains:

| Deleted | What | Recoverable |
|---|---|---|
| `System32\Microsoft\Protect\S-1-5-18\*` | DPAPI master keys of SYSTEM | no (unique per install) |
| `System32\Tasks\*` | scheduled task XMLs | rebuild from `TaskCache` registry |
| `System32\AppLocker\*` | AppLocker cache | regenerated |
| `System32\PerfStringBackup.INI` | perf counter backup | `lodctr /R` |
| `System32\WinBioDatabase\*.DAT` | biometrics | re-enroll |
| `SysWOW64\PrintConfig.dll` | copy from DriverStore | from DriverStore |

Lesson: the tool also needs a "machine state" inventory: files that aren't in the WIM but
must exist (DPAPI keys, Tasks, …), reported as **unrecoverable / rebuildable**.

## 2026-11-12 — ✅ It boots

The missing piece was **empty directories**. The planner only created folders that needed
files, so 92 WIM directories stayed gone, including `System32\GroupPolicy` /
`GroupPolicyUsers` (→ `gpsvc` failure), `SysWOW64\config\{Journal,RegBack,TxR}`,
`SysWOW64\LogFiles\{LSA,SAM}`, `sru`, `SMI\Store`, `wbem\Repository`, `Tasks` skeleton.
76 restored with WIM ACLs (16 belonged to a removed WinSxS component → skipped).
After that the VM **booted straight to the desktop**.

Full repair for "deleted everything deletable in System32 and SysWOW64":

1. 573 files: 531 hardlinks to WinSxS + 42 extracted (with WIM security descriptors)
2. 76 + 107 directories (with WIM security descriptors)
3. no registry changes needed (verified with own log replay)
4. `ntfsfix -d` twice to get read-write (dirty volume) — WinPE would avoid this

Not restored (not in any WIM): SYSTEM DPAPI master keys, Task XMLs, AppLocker cache,
`PerfStringBackup.INI`, WinBio DB. Windows booted anyway.

Also learned: `servicing\Sessions\Sessions.xml` is **WOF-compressed** (reparse tag
`0x80000017`). ntfs-3g without the `system-compression` plugin shows it as a broken
symlink → hash lists miss it. Need the plugin on Linux, or handle WOF on both backends.

## 2026-11-12 — ✅ Registry blind test: boots again

User deleted keys in SOFTWARE and SYSTEM (unknown which). Symptom: `0xEF
CRITICAL_PROCESS_DIED` right after the boot spinner.

### What it took (4 attempts)

1. **WIM merge only** (add missing keys/values, `X:` → `C:` in names and data):
   SOFTWARE +18 877 keys. Still 0xEF. Two bugs found:
   - hivex writes values > 16 344 bytes as one plain cell; Windows needs a `db`
     (big data) record and blanks the value → `proto/bigdata.py` converts them.
   - normal-diff "state areas" were excluded completely, hiding the real damage.
2. **Undelete from free cells** (`proto/hiveundelete.py`): deleted keys stay in the hive
   until their cells are reused. 1 558 keys recovered from the broken hive itself
   (incl. user `ProfileList` entry, `SecurityManager\CapAuthz`, `IFEO\LSASS.exe`).
   Only 3 were Windows' own old deletions (harmless). Still 0xEF.
3. **Diagnosis**: `DumpStack.log.tmp` in the volume root holds bugcheck code + params
   even when no dump survives. Set a dedicated dump file via CrashControl. The crash
   now happened *before* the dump stack initialised (no pagefile created) → very early
   (smss/csrss stage). Counting keys showed SOFTWARE 46 000 keys short of healthy:
   **`SideBySide\Winners` (34 151 keys) completely gone**, plus most of CBS, Appx store,
   Capabilities — all inside "state areas" the diff skips.
4. **Lost-state rule**: a state *database* (SideBySide, CBS, Appx store, Capabilities)
   with > 50 % of the WIM's keys missing is restored from the WIM. CBS packages only if
   their `.mum` is on disk (19 removed packages stayed removed). Consumed queues
   (RunOnce, Print\PackagesToAdd, …) are never restored. Healthy baseline: nothing to do.
   → **boots**.

### Repair order (registry)

1. replay transaction logs (`hivelog.py`)
2. undelete intact keys from free cells (machine's own data, best source)
3. restore lost state databases from WIM
4. add remaining missing keys/values from WIM (`X:` → `C:`)
5. convert big values to `db` records
6. swap hive in, back up original, empty `.LOG1/.LOG2`

### Sources, none of which needs a backup

| Source | From |
|---|---|
| transaction logs | broken PC |
| free cells | broken PC |
| WIM | ISO of the same build |

Result vs. healthy state (measured only, not used): 264 018 / 265 029 keys. The rest is
runtime state (LogonUI notifications, DiagTrack, consent store) Windows recreates.

## 2026-11-12 — ✅ SYSTEM blind test: boots again

User deleted ~3 156 keys in SYSTEM (incl. `Control\Lsa\{JD,Skew1,GBG,Data}`, ACPI, AppID,
CrashControl, per-user service templates). Symptom: instant blue screen before the spinner.

Also found: the previous SOFTWARE repair had grown the hive to **1.4 GB** (hivex appends a
new bin for almost every added key). SYSTEM would have gone 11 MB → 312 MB, which the boot
loader can't load.

### New pieces

- **`proto/hivecompact.py`**: loads a hive into memory and writes a fresh compact hive
  (sorted lh lists + ri index, lh hashes, deduplicated sk list, class names, flags, access
  bits, timestamps, big data as full-size 16 344-byte segments like Windows). Verified
  content-identical on SYSTEM and SOFTWARE (264 588 keys). SOFTWARE 1.4 GB → 76 MB.
- **`proto/regrepair2.py`**: whole repair in memory, written by the compactor. No hivex
  writes any more.
- Deleted keys have their security pointer cleared by Windows (`0xFFFFFFFF`) → descriptor
  comes from the WIM key, else the parent (= inheritance).
- **Boot key recovery**: the Lsa class names (boot key → SAM) were gone with the keys.
  - Skew1: from a free nk record.
  - JD/GBG/Data: their class-name cells survived as free cells; *stale nk records in
    `SYSTEM.LOG1`* still pointed at them → exact mapping, no guessing.
  - All four identical to pre-break (checked afterwards).
  - Rule: old nk records in transaction logs supply class names for restored keys.
- **PnP reinstall**: devices whose `Control\Class\{guid}\NNNN` driver key is gone get
  `ConfigFlags |= CONFIGFLAG_REINSTALL (0x20)`; PnP rebuilds class/interface keys. 14
  devices (incl. `ROOT\volmgr`, TPM).

Result: boots without problems. 778 hardware-generated keys (Class instances,
DeviceClasses, Power, NSI) were left to Windows/PnP to recreate.

## Summary of the three blind tests

| Test | Broken | Repaired from | Result |
|---|---|---|---|
| Files | all deletable files in System32 + SysWOW64 | WIM (hardlinks to WinSxS + extraction), WIM ACLs, empty dirs | boots |
| SOFTWARE | keys incl. SxS Winners, CBS, Appx, CapAuthz | logs, free cells, lost-state DBs from WIM, WIM merge | boots |
| SYSTEM | keys incl. Lsa boot key, ACPI, Class | logs, free cells, stale log records (boot key), WIM, PnP reinstall | boots |

No backup was used for any repair. The healthy install gets zero actions.
