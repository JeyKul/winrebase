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
