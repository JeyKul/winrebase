# Roadmap

## M0 — Test lab
- [ ] Windows 11 VM (UEFI + TPM), known build, `clean` snapshot
- [ ] Matching WIM from UUP dump, check it really matches
- [ ] Scripts that break the VM for scenarios 1–4 from the host

## M1 — Read-only analyzer (Linux first, quickest to iterate)
- [ ] Read build/UBR/edition from offline hive
- [ ] Open WIM/ESD, pick matching index, verify build from the image's own hive
- [ ] File diff over `\Windows` with exclusions → `plan.json`
- [ ] Registry diff (add-missing rule) → `plan.json`
- [ ] Human-readable dry-run report
- [ ] Does it find the broken bits from scenarios 1–4?

## M2 — Apply (Linux)
- [ ] Rollback set
- [ ] Pending update cleanup
- [ ] File restore/replace with ACLs, hardlinks, reparse points
- [ ] Registry merge via hivex
- [ ] Verify pass
- [ ] Scenarios 1–7 pass

## M3 — WinPE backend
- [x] Win32 file backend (wimlib extract, hardlinks to intact copies, WIM ACLs)
- [x] Hive backend: own pure-Rust reader/writer (`app/src/reg`), no `RegLoadKey`/`offreg.dll`
  (the WinPE kernel would write to the broken hive when loading it)
- [x] Registry stage: log replay with gap check, undelete, lost state DBs, WIM merge,
  IDConfigDB, driver keys, clean device start
- [x] WinPE build script (`tools/build-iso.sh`, takes the Windows .iso directly)
- [x] WIM/ESD from an .iso inside WinPE (VirtDisk attach, Browse or Search)
- [ ] Scenarios 1–10 pass

## M4 — Usability
- [x] Simple native GUI (Analyze / Repair, progress, log)
- [ ] Bootable images published as releases
- [ ] Docs for technicians

## Later
- [ ] "Patch registry" when restoring an older/other build: bring SOFTWARE/SYSTEM/COMPONENTS
  servicing state (UBR, CBS packages, component ownership) in line with the files restored
- [ ] Detect COMPONENTS ≠ SOFTWARE CBS rollup version (wrong WIM poured over, aborted
  rollback) → full restore with `--replace` semantics, COMPONENTS from the WIM
- [ ] Clear stuck CBS state (`ExecuteState`, `SessionsPending`) after an aborted rollback
- [ ] Manifest-based registry check without a WIM (`WinSxS\Manifests`)
- [ ] Extra sources for FODs / language packs / optional features
