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
