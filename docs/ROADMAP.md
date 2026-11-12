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
- [ ] Win32 file backend (`BackupWrite`, hardlinks, reparse points)
- [ ] Hive backend (`offreg.dll` or `RegLoadKey`)
- [ ] WinPE build script (inject binary + deps)
- [ ] Scenarios 1–10 pass on both backends

## M4 — Usability
- [ ] TUI / simple GUI
- [ ] Bootable images published as releases
- [ ] Docs for technicians

## Later
- [ ] Manifest-based registry check without a WIM (`WinSxS\Manifests`)
- [ ] Extra sources for FODs / language packs / optional features
