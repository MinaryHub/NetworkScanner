#!/usr/bin/env sh
# data/ouiinfo.ini(MAC OUI → 제조사 테이블)를 IEEE 공개 데이터로 갱신한다.
# ouiinfo.ini는 IEEE oui.txt 원문 그대로이며(OUIInfo.LoadInfo가 "(hex)" 줄을 직접 파싱), 별도 변환이 필요 없다.
# 예전의 Windows 전용 OUIConvertor(WPF)를 대체한다. 어느 OS에서든 실행 가능.
#
#   sh tools/update-oui.sh
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/data/ouiinfo.ini"
URL="https://standards-oui.ieee.org/oui/oui.txt"
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

echo "Downloading $URL ..."
curl -fsSL --retry 3 "$URL" -o "$TMP"

COUNT=$(grep -c '(hex)' "$TMP" || true)
if [ "$COUNT" -lt 10000 ]; then
  echo "Downloaded file looks wrong (only $COUNT OUI entries) - keeping the existing $OUT" >&2
  exit 1
fi

mv "$TMP" "$OUT"
trap - EXIT
echo "Updated $OUT ($COUNT OUI entries)"
