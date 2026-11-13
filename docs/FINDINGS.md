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

## 2026-11-12 — Test 4: "pour the WIM back" + boot partition gone

Damage (done from the install ISO, so in-use files could be deleted too):
- **GPT entry of the EFI partition deleted.** Firmware fell through to the CD. Content of
  the ESP untouched (FAT32 boot sector at 1 MiB, all 147 files).
- **~108 000 of ~121 000 files under `\Windows` deleted**: nearly all of System32/SysWOW64,
  `servicing\Packages`, most of WinSxS, `Temp`, the hives `COMPONENTS`, `ELAM`,
  `BCD-Template`, and the tool's own `winrebase-backup`.
- Registry hives SYSTEM/SOFTWARE/SAM/SECURITY/DEFAULT/DRIVERS survived, essentially intact.

### Repair

1. **GPT**: re-created the ESP entry from the FAT32 boot sector (start 2048, 204 800
   sectors), type ESP, **original partition GUID** (the BCD references it), attribute 63
   (no drive letter), moved back to slot 1 (`sgdisk -n/-t/-u/-A`, `--transpose`).
2. **`proto/fullrestore.py`** (the original WIM idea): when damage is massive, WinSxS folders
   and `COMPONENTS` can't be the authority any more. Restore everything the WIM has and the
   volume lacks, except exclusions, known moves and CBS packages the SOFTWARE hive doesn't
   list (38 skipped).
   - 8 739 files re-linked to surviving WinSxS twins
   - 99 510 files extracted with `wimextract` (keeps hardlink groups: 51 649 linked files),
     packed as tar, `tar-in` on an ntfs-3g mount (keeps hardlinks) → 7.5 GB in ~30 s
   - 20 265 directories; security descriptors from the WIM for every restored file/dir
     (once per hardlink group), 0 failures
   - `COMPONENTS`, `ELAM`, `BCD-Template` from the WIM
3. Result: 121 314 files identical to the WIM; only the 39 intentional skips differ.

Caveats:
- `COMPONENTS` from the WIM predates post-install servicing (e.g. WMIC removal). Servicing
  metadata may be slightly inconsistent → check `DISM /ScanHealth`.
- `\Windows\Temp` was gone: scripts must not assume it exists (now run from the volume root).

## 2026-11-12 — Test 5: System32 files + SOFTWARE/SYSTEM keys deleted, torn hives

Damage (as TrustedInstaller, from the running system): files in `System32` deleted, then
~15 000 SOFTWARE keys and large parts of SYSTEM (`Control\Class` instances,
`Control\IDConfigDB`, `DeviceClasses`, Lsa) deleted in regedit. Windows died; the WinPE app
then restored the files (hashes = WIM), but the VM still stopped with **0xc0000001** in the
boot manager. The WinPE app had **no registry stage at all** — files only.

Hive state found:

| Hive | Primary seq | Log entries | |
|---|---|---|---|
| SYSTEM | 457/456 (dirty) | 475–478 | **gap** 456–474 → unrecoverable from logs |
| DEFAULT | 48/47 (dirty) | 52, 53 | gap |
| SECURITY | 137/136 | 136, 131–135 | recoverable |
| SOFTWARE | 1140/1140 | older | clean, but ~15 000 keys deleted |

Bisected on qcow2 overlays (original disk never touched), each step = one boot:

1. **`hivelog.py` bug**: log entries were applied even when the first one didn't continue
   the primary (seq ≠ seq2). Applying 475+ onto 456 corrupts the hive. Fixed: replay must
   start at `seq2`; on a gap the primary is used as is (it was structurally clean here).
2. SOFTWARE repaired by `regrepair2.py` → fine.
3. SYSTEM: **0xc0000001** → `Control\IDConfigDB` came back from the WIM. The WIM copy is
   the *pre-setup template* (`CurrentConfig 0`, only the "Pristine" profile 0000); Setup
   clones it to 0001+. Rule `fix_hwprofile`: rebuild IDConfigDB from the profiles still
   under `<CS>\Hardware Profiles`.
4. Then **0x69 IO1_INITIALIZATION_FAILED** (kernel I/O init):
   - Rule `fix_devices`: the driver key `Control\Class\{guid}\NNNN` is rebuilt from the
     device's own driver properties `Enum\…\Properties\{a8b865dd-…}` (DriverDesc, Version,
     Date, InfPath, InfSection, MatchingDeviceId, Provider) — byte-identical to the lost
     key. `CONFIGFLAG_REINSTALL` only for keys that can't be rebuilt or the Net class, and
     **never for boot/system-start drivers** (flagging AHCI/disk/volume → no boot device).
   - Still 0x69: bisecting `Control` subtrees → `DeviceClasses`. Keys **undeleted** from
     free cells there break it (with the machine's partial `DeviceClasses` and no undelete
     it boots). Pruning interface keys without `#` subkey wasn't it (the healthy hive has
     7 such keys).
5. **Clean device start** (`proto/devreset.py`): `Enum`, `DeviceClasses`,
   `DeviceContainers`, `Class\{guid}\NNNN` and the start type of every boot-start service
   taken from the WIM. The WIM is generalized and boots on any hardware; Windows
   re-detects all devices on first boot ("Getting devices ready"). **Boots.**

Rules learned:
- Never apply transaction-log entries across a sequence gap.
- WIM keys that Setup *specializes* (IDConfigDB) must not be restored verbatim.
- PnP device state is the most fragile part; undelete is unsafe there. Offer
  **clean device start** as an option (and the automatic fallback when `Control\Class`
  or `Enum` lost a lot).

### Test 5, part 2: after it boots — profile, apps, Start menu

Booted, but logon gave a fresh profile; Start menu, Settings, CrossDevice ("Die Anwendung
wurde nicht bereitgestellt") and Terminal ("Das System kann auf die Datei nicht zugreifen")
failed. Diffed against the healthy `win11-2-clone` (same build; the tool gives it 0 actions)
and read the event logs offline (python-evtx). Four more rules, all in `app/src/reg`:

| Damage | Effect | Rule |
|---|---|---|
| `ProfileList\<SID>` deleted | Windows makes `admin.MINWINPC`, an empty profile | rebuild from the account SID found in each `Users\*\NTUSER.DAT` (most frequent user SID in its security descriptors); point back to the oldest folder if Windows already made a duplicate |
| `ComputerName` from the WIM | name is the WIM placeholder `MINWINPC` | take `Tcpip\Parameters\Hostname` |
| `Appx\AppxAllUserStore\<SID>\*` (46 of 92) | per-user app bookkeeping gone | rebuild from `InboxApplications` + `Applications` (exactly the user's list on a healthy install) when ≥ 10 % are missing and the package files exist |
| `SecurityManager\CapAuthz\ApplicationsEx` (2 of 99 left) | no package token: AppModel-Runtime 206 `GetPackageToken` | rebuild from `ProgramData\…\AppRepository\<package>.xml` (see below) |

**CapAuthz** holds one entry per main package: `PackageSid`, `CapSids`, `DeviceCapSids`,
`CustomCapSids`, `AppPackageType`, `EnterpriseID`, `ApplicationFlags`. Everything is derived
from names:

- package SID `S-1-15-2-` + first 7 DWORDs of SHA-256(lowercase family name, UTF-16LE)
- capability SID `S-1-15-3-<rid>` for the 12 well-known capabilities, else
  `S-1-15-3-1024-` + 8 DWORDs of SHA-256(UPPERCASE name, UTF-16LE)
- `CapSids` = declared `Capability`/`DeviceCapability` names (+ `cellularData`, `wifiData`
  with internet access; never `unvirtualizedResources`) + the package's own `S-1-15-3-<hash>`
- `DeviceCapSids` = `S-1-15-3-<GUID>` from `DeviceAccess\CapabilityMappings\<capability>`
- blob = count + SIDs + the same number of zero bytes
- Settings has `AppPackageType` 2

Against the clone: 52/99 byte-exact, 23 same SIDs in another order, 24 missing some implicit
grants (Bluetooth/web host). Re-registering with `Add-AppxPackage -Register` rebuilds these
entries for Store apps but **not for system apps** — that's why Start/Settings stayed broken.
With the rule: **Start menu works.**

Tool notes from this round:
- WinPE showed a black screen in the VM while its network link was up (app window appears,
  then black). Disabling the link fixed it; cause not yet known.
- Host TPM passthrough and the q35 watchdog (`itco`, action reset) were removed from the
  test VM while hunting this; neither was the cause.

## 2026-11-13 — Real case: Win11 Pro 26300.9550, 0xc0000001

Customer PC, boot manager stops with **0xc0000001**; real hardware power-cycles once during
boot. Disk imaged (qcow2, read-only base), tested on overlays in a VM without network.
WIM: index with the exact build (26300.9550 Pro). Every step bisected on its own overlay.

History, from `CBS.log` and the files:
1. Cumulative update installed, reboot pending.
2. PC started in **Safe Mode** with the update pending → `0x800f0923
   CBS_E_SAFEMODE_ENTERED`, rollback started, then `Failed to query for a cmdline to use for
   Poqexec` → rollback stopped halfway (`ExecuteState` 3, `CrossRebootHresult` 0x800f0923).
3. A repair attempt copied **26200.6584 media** files over `\Windows`, including
   `COMPONENTS` (file date 2025-09-15, seq 123; its own `.LOG1` still had seq 2506+ with the
   real 9549/9711/9818 data).

State found: SOFTWARE (UBR, CBS `RollupFix 26100.9550` installed) and the WinSxS payload at
9550; System32 hardlinked to the 6584 components; COMPONENTS from 6584.

Why the tool didn't fix it: COMPONENTS didn't know the 9549 components, so every differing
System32 file was skipped as "component not installed (staged)".

| Overlay | Change | Result |
|---|---|---|
| A | as found (after two tool runs) | 0xc0000001 |
| B | 11 350 files back to the WIM (10 031 re-linked to intact 9549 twins, 2 233 extracted), COMPONENTS from the WIM, `ExecuteState` 0 | 0xc0000001 |
| C | B + original SYSTEM | 0xc0000001 |
| E | B + the WIM's SYSTEM | past winload (black screen, mismatched hives) |
| F | C + 6 third-party boot drivers off (Kaspersky, Roxio) | 0xc0000001 |
| G | F + `DeviceGuard\EnableVirtualizationBasedSecurity` 0 | **boots to the desktop** |

`\Windows\bootstat.dat` (winload's log) showed the failing step: event 0xeb (0xc0000002)
then 0xd0 (0xc0000001) after loading the CI policies — the hypervisor / secure kernel launch
for VBS. That also explains the power cycle on real hardware.

Not the cause: ESP and BCD (boot manager 28000.367 is what 26300.9550 ships; BCD clean),
IDConfigDB, the third-party boot drivers.

New in the tool:
- **Stale COMPONENTS**: WIM component folders present on disk but unknown to COMPONENTS.
  Healthy 0.04 %, this case 31 % → over 10 % = full restore mode, COMPONENTS from the WIM.
- **Servicing reset**: after a full restore, `ExecuteState` → 0 when
  `SessionsPending\CrossRebootHresult` is a failure (fresh images have `ExecuteState` 3
  without a failure — left alone).
- **Turn off VBS** option (VBS + HVCI `Enabled` → 0); Analyze hints at it when VBS is on.
- `fullrestore.py --replace` for the prototype path.
- Undelete only where the hive is damaged (two earlier tool runs undeleted 532 feature
  override keys Windows had removed itself).

Hive edits during the bisect were in-place DWORD patches (one byte each), never a rewrite.
