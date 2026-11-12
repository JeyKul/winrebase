#!/bin/sh
# Build a bootable WinPE test ISO with winrebase.exe starting automatically.
#
#   tools/build-iso.sh <mounted Windows ISO dir> [output.iso]
#
# Uses WinPE (index 1 of sources/boot.wim) and the boot files from that ISO. The result
# is for your own testing; it contains Microsoft files, don't redistribute it.
set -eu
SRC=${1:?usage: build-iso.sh <mounted Windows ISO dir> [output.iso]}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${2:-$ROOT/build/winrebase-pe.iso}
EXE=$ROOT/app/target/x86_64-pc-windows-gnu/release/winrebase.exe
WORK=$ROOT/build/iso
[ -f "$EXE" ] || { echo "build the exe first: (cd app && cargo build --release)"; exit 1; }

rm -rf "$WORK" && mkdir -p "$WORK/sources"
for f in bootmgr bootmgr.efi boot efi; do cp -r "$SRC/$f" "$WORK/"; done
chmod -R u+w "$WORK"

# WinPE image: export index 1 as the bootable image, add the tool
wimlib-imagex export "$SRC/sources/boot.wim" 1 "$WORK/sources/boot.wim" --boot
cat > "$ROOT/build/winpeshl.ini" <<'INI'
[LaunchApps]
%SYSTEMROOT%\System32\wpeinit.exe
%SYSTEMROOT%\System32\winrebase.exe
%SYSTEMROOT%\System32\cmd.exe
INI
wimlib-imagex update "$WORK/sources/boot.wim" 1 <<CMDS
add '$EXE' /Windows/System32/winrebase.exe
add '$ROOT/build/winpeshl.ini' /Windows/System32/winpeshl.ini
CMDS

xorriso -as mkisofs -iso-level 3 -full-iso9660-filenames -J -joliet-long -R \
  -V WINREBASE \
  -b boot/etfsboot.com -no-emul-boot -boot-load-size 8 -boot-info-table \
  -eltorito-alt-boot -e efi/microsoft/boot/efisys_noprompt.bin -no-emul-boot \
  -o "$OUT" "$WORK" 2>&1 | grep -v '^xorriso : UPDATE' || true
ls -la "$OUT"
