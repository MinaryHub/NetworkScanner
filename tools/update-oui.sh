#!/usr/bin/env sh
# data/ouiinfo.ini(MAC OUI → 제조사 테이블)를 IEEE 공개 데이터로 갱신한다.
# ouiinfo.ini는 IEEE oui.txt 원문 그대로이며(OUIInfo.LoadInfo가 "(hex)" 줄을 직접 파싱), 별도 변환이 필요 없다.
# 예전의 Windows 전용 OUIConvertor(WPF)를 대체한다. 어느 OS에서든 실행 가능.
#
#   sh tools/update-oui.sh
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)

# 파일, URL, 최소 항목 수. MA-L(24비트) 외에 MA-M(28비트)·MA-S(36비트) 블록도 받아 작은 제조사까지 찾는다.
fetch() {
  OUT="$ROOT/data/$1"; URL="$2"; MIN="$3"
  TMP=$(mktemp)
  echo "Downloading $URL ..."
  if ! curl -fsSL --retry 3 "$URL" -o "$TMP"; then rm -f "$TMP"; echo "download failed: $URL" >&2; return 1; fi
  COUNT=$(grep -c '(hex)' "$TMP" || true)
  if [ "$COUNT" -lt "$MIN" ]; then rm -f "$TMP"; echo "Downloaded file looks wrong (only $COUNT entries) - keeping $OUT" >&2; return 1; fi
  mv "$TMP" "$OUT"; chmod 644 "$OUT"
  echo "Updated $OUT ($COUNT entries)"
}

fetch ouiinfo.ini     https://standards-oui.ieee.org/oui/oui.txt     10000
fetch ouiinfo-mam.ini https://standards-oui.ieee.org/oui28/mam.txt   2000
fetch ouiinfo-mas.ini https://standards-oui.ieee.org/oui36/oui36.txt 2000
