# Risks and open questions

The user is responsible, but the tool should still catch the obvious ways to brick a PC.

## Known risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| WIM build ≠ installed build | almost certain boot failure (mixed DLL versions, WinSxS out of sync) | hard check on build + UBR + edition, no override in v1 |
| No backup | data loss if anything goes wrong | required confirmation + rollback set |
| BitLocker locked | can't read volume | detect, explain how to unlock |
| Hibernated / Fast Startup volume | corruption when Windows resumes | refuse, or `--discard-hibernation` |
| Broken hardlinks WinSxS ↔ System32 | disk usage doubles, servicing errors | re-create links from WIM link info |
| Wrong ACLs | services fail, TrustedInstaller loses ownership | copy security descriptors from WIM |
| OEM / vendor changes to Windows files | vendor customisations reverted | that's the point; report them in the plan |
| Inbox driver replaced while a newer OEM one is in use | device stops working | drivers outside the WIM are kept; report inbox-driver replacements |
| Registry value reset (`--reset-values`) | settings, service start types lost | off by default |
| Optional features / FODs / language packs installed later | files present in install, not in WIM → kept, but their registry may be incomplete | document; later: support multiple WIM/FOD sources |
| Activation / licensing | possibly reset | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform` excluded, test it |
| Windows Defender / tamper protection | might block or flag changes after boot | we work offline; test behaviour on first boot |

## Open questions

- **Does UUP dump give a bit-identical match?** An ISO built for UBR X should contain the
  same component versions as a machine updated to X via Windows Update. Needs testing; there
  may be differences from Dynamic Update / SSU / out-of-band patches.
- **ESD vs WIM**: `install.esd` is solid-compressed (LZMS). `wimlib` reads it, but random
  access is slow. Probably convert to WIM first.
- **`COMPONENTS` hive**: replace from WIM or keep? It's tied to WinSxS state. If the build
  matches, replacing it should be consistent. To test.
- **Multiple ControlSets**: newer Windows only has `ControlSet001`. Handle older layouts anyway.
- **Per-user `UsrClass.dat`**: compare against what? Probably against the default profile's,
  only adding missing keys.
- **WinPE hive writing**: `offreg.dll` isn't in WinPE by default, needs to be shipped (WDK
  redistributable). Alternative: `RegLoadKey` with backup/restore privilege.
- **Linux: `ntfs-3g` and WOF-compressed files**: reading is supported via the `ntfs-3g-system-compression`
  plugin; writing compressed is not. Restored files would be uncompressed → more disk usage. Acceptable?
- **Disk space**: replacing thousands of files needs free space for the rollback set. Check first.
