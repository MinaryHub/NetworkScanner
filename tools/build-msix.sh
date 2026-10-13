#!/usr/bin/env sh
# KetworkScanner GUI 를 MSIX 로 패키징한다(macOS/Linux). Microsoft MSIX SDK 의 makemsix 가 필요하다
# (https://github.com/microsoft/msix-packaging, cmake -DMSIX_PACK=on). Windows 에서는 tools/build-msix.ps1 을 쓴다.
#
#   sh tools/build-msix.sh [win-x64|win-arm64] [출력 폴더]
#
# 환경 변수(Partner Center 의 Product identity 값; 비우면 사이드로드 테스트용 기본값):
#   MSIX_IDENTITY_NAME   (예: 12345SMIC.KetworkScanner)   기본 SMIC.KetworkScanner
#   MSIX_PUBLISHER       (예: CN=0A1B2C3D-...)             기본 CN=SMIC
#   MSIX_PUBLISHER_DISPLAY                                 기본 SMIC
#   MSIX_VERSION         (x.y.z.0)                         기본 csproj 의 <Version>.0
#   MAKEMSIX             makemsix 실행 파일 경로            기본 PATH 에서 찾음
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
RID=${1:-win-x64}
OUT=${2:-"$ROOT/release-packages/msix"}
case "$RID" in
  win-x64) ARCH=x64 ;;
  win-arm64) ARCH=arm64 ;;
  *) echo "unsupported RID: $RID (win-x64|win-arm64)" >&2; exit 2 ;;
esac
PROJ="$ROOT/KetworkScanner.Avalonia/KetworkScanner.Avalonia.csproj"
CSPROJ_VERSION=$(sed -n 's#.*<Version>\([0-9.]*\)</Version>.*#\1#p' "$PROJ" | head -1)
VERSION=${MSIX_VERSION:-"$CSPROJ_VERSION.0"}
IDENTITY=${MSIX_IDENTITY_NAME:-SMIC.KetworkScanner}
PUBLISHER=${MSIX_PUBLISHER:-CN=SMIC}
PUBLISHER_DISPLAY=${MSIX_PUBLISHER_DISPLAY:-SMIC}
MAKEMSIX=${MAKEMSIX:-makemsix}

STAGE=$(mktemp -d)
trap 'rm -rf "${STAGE:?}"' EXIT
echo "Publishing $RID (StoreBuild) ..."
dotnet publish "$PROJ" -c Release -r "$RID" --self-contained -p:StoreBuild=true -p:Version="$CSPROJ_VERSION" -o "$STAGE/app" --nologo -v q

# 패키지 루트: 실행 파일 + 데이터 파일 + Assets + AppxManifest.xml
PKG="$STAGE/pkg"
mkdir -p "$PKG/Assets"
cp -R "$STAGE/app/." "$PKG/"
cp "$ROOT/KetworkScanner.Avalonia/Package/Assets/"*.png "$PKG/Assets/"
find "${PKG:?}" -maxdepth 1 -name '*.pdb' -delete
sed -e "s#__IDENTITY_NAME__#$IDENTITY#" -e "s#__PUBLISHER__#$PUBLISHER#" -e "s#__PUBLISHER_DISPLAY__#$PUBLISHER_DISPLAY#" \
    -e "s#__VERSION__#$VERSION#" -e "s#__ARCH__#$ARCH#" \
    "$ROOT/KetworkScanner.Avalonia/Package/AppxManifest.xml" > "$PKG/AppxManifest.xml"

mkdir -p "$OUT"
MSIX="$OUT/KetworkScanner-$VERSION-$ARCH.msix"
[ -f "$MSIX" ] && rm -f "${MSIX:?}"
echo "Packing $MSIX ..."
"$MAKEMSIX" pack -d "$PKG" -p "$MSIX"
ls -l "$MSIX"
echo "Unsigned package (Store signs on submission). Sideload test on Windows: sign with a cert whose subject equals '$PUBLISHER'."
