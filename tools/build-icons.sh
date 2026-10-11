#!/usr/bin/env sh
# assets/icon/*.svg 원본에서 앱 아이콘 파일을 다시 만든다. ImageMagick(magick)이 필요하고, .icns는 macOS(iconutil)에서만 만든다.
#   sh tools/build-icons.sh
# 산출물: assets/app.ico(16~256 다중 크기, Windows), assets/app.icns(macOS), assets/app.png(512, Linux/AppImage), assets/logo.png(64, 사이드바)
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC="$ROOT/assets/icon"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

for s in 1024 512 256 128 64 48; do
  magick -background none "$SRC/app-icon.svg" -resize ${s}x${s} "$TMP/app-$s.png"
done
# 32px 이하는 단순화 글리프를 쓴다.
for s in 32 16; do
  magick -background none "$SRC/app-icon-small.svg" -resize ${s}x${s} "$TMP/app-$s.png"
done

magick "$TMP/app-16.png" "$TMP/app-32.png" "$TMP/app-48.png" "$TMP/app-64.png" "$TMP/app-128.png" "$TMP/app-256.png" "$ROOT/assets/app.ico"
cp "$TMP/app-512.png" "$ROOT/assets/app.png"
cp "$TMP/app-64.png" "$ROOT/assets/logo.png"

if command -v iconutil >/dev/null 2>&1; then
  mkdir -p "$TMP/app.iconset"
  cp "$TMP/app-16.png"   "$TMP/app.iconset/icon_16x16.png"
  cp "$TMP/app-32.png"   "$TMP/app.iconset/icon_16x16@2x.png"
  cp "$TMP/app-32.png"   "$TMP/app.iconset/icon_32x32.png"
  cp "$TMP/app-64.png"   "$TMP/app.iconset/icon_32x32@2x.png"
  cp "$TMP/app-128.png"  "$TMP/app.iconset/icon_128x128.png"
  cp "$TMP/app-256.png"  "$TMP/app.iconset/icon_128x128@2x.png"
  cp "$TMP/app-256.png"  "$TMP/app.iconset/icon_256x256.png"
  cp "$TMP/app-512.png"  "$TMP/app.iconset/icon_256x256@2x.png"
  cp "$TMP/app-512.png"  "$TMP/app.iconset/icon_512x512.png"
  cp "$TMP/app-1024.png" "$TMP/app.iconset/icon_512x512@2x.png"
  iconutil -c icns "$TMP/app.iconset" -o "$ROOT/assets/app.icns"
else
  echo "iconutil not found - app.icns not rebuilt (macOS only)" >&2
fi
echo "icons rebuilt under $ROOT/assets"
