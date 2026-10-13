#!/usr/bin/env sh
# data/reservedports.ini(참고 포트 목록)를 IANA 서비스 이름/포트 번호 레지스트리로 갱신한다.
# 형식은 기존과 같은 "TCP,<port>,<설명>" 한 줄씩이며, IANA에 없는 기존 항목(수작업으로 넣은 트로이/백도어 포트 등)은 그대로 남긴다.
#
#   sh tools/update-ports.sh
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/data/reservedports.ini"
URL="https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
TMP=$(mktemp)
echo "Downloading $URL ..."
curl -fsSL --retry 3 "$URL" -o "$TMP"
python3 - "$TMP" "$OUT" <<'PY'
import csv, re, sys
src, out = sys.argv[1], sys.argv[2]
rows = {}
with open(src, newline="", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        if (r.get("Transport Protocol") or "").strip().lower() != "tcp": continue
        port = (r.get("Port Number") or "").strip()
        if not re.fullmatch(r"\d+", port): continue          # 범위("1-2")는 건너뛴다
        p = int(port)
        if p > 65535 or p in rows: continue                   # 포트당 첫 항목만
        desc = re.sub(r"\s+", " ", (r.get("Description") or "").strip())
        name = (r.get("Service Name") or "").strip()
        text = desc or name
        if not text or text.lower().startswith("unassigned"): continue   # 미할당 포트는 목록에 넣지 않는다
        rows[p] = text
# 기존 파일의 수작업 항목 보존(IANA에 없는 포트)
try:
    with open(out, encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split(",", 2)
            if len(parts) == 3 and parts[0].strip().upper() == "TCP" and parts[1].strip().isdigit():
                p = int(parts[1]); 
                if p not in rows and parts[2].strip() and not parts[2].strip().lower().startswith("unassigned"): rows[p] = parts[2].strip()
except FileNotFoundError:
    pass
if len(rows) < 1000:
    sys.exit("too few rows (%d) - keeping the existing file" % len(rows))
with open(out, "w", encoding="utf-8", newline="\n") as f:
    for p in sorted(rows):
        f.write("TCP,%d,%s\n" % (p, rows[p]))
print("Updated %s (%d ports)" % (out, len(rows)))
PY
rm -f "$TMP"
