#!/bin/sh
# Cross-compile wimlib as a static MinGW library into third_party/wimlib-win64.
set -eu
VER=1.14.5
SHA=84221a3abd5b91228f15f8e6065c335a336237b5738197b75bf419eea561a194
ROOT=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$ROOT/third_party/src"
cd "$ROOT/third_party/src"
[ -f wimlib-$VER.tar.gz ] || curl -fsSLO https://wimlib.net/downloads/wimlib-$VER.tar.gz
echo "$SHA  wimlib-$VER.tar.gz" | sha256sum -c -
rm -rf wimlib-$VER && tar xzf wimlib-$VER.tar.gz && cd wimlib-$VER
./configure --host=x86_64-w64-mingw32 --enable-static --disable-shared CFLAGS=-O2 >/dev/null
make -j"$(nproc)" libwim.la >/dev/null
mkdir -p "$ROOT/third_party/wimlib-win64/lib" "$ROOT/third_party/wimlib-win64/include"
cp .libs/libwim.a "$ROOT/third_party/wimlib-win64/lib/"
cp include/wimlib.h "$ROOT/third_party/wimlib-win64/include/"
echo "wimlib $VER -> third_party/wimlib-win64"
