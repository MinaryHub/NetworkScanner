#!/usr/bin/env sh
# data/refdata.json(참조 데이터 매니페스트)을 다시 만든다. 앱은 이 파일로 저장소의 데이터가 번들보다 새로운지 판단한다.
# 내용(SHA-256)이 바뀐 파일만 오늘 날짜(UTC)로 버전이 올라가고, 바뀌지 않은 파일은 기존 버전을 유지한다.
#
#   sh tools/refdata-manifest.sh
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
python3 - "$ROOT/data" <<'PY'
import hashlib, json, os, sys, datetime
d = sys.argv[1]
names = ["reservedports.ini", "prohibitports.ini", "vulnrules.json", "ouiinfo.ini", "ouiinfo-mam.ini", "ouiinfo-mas.ini"]
path = os.path.join(d, "refdata.json")
old = {}
if os.path.exists(path):
    with open(path, encoding="utf-8") as f:
        old = {x["name"]: x for x in json.load(f).get("files", [])}
today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
files = []
for n in names:
    p = os.path.join(d, n)
    if not os.path.exists(p): continue
    data = open(p, "rb").read()
    sha = hashlib.sha256(data).hexdigest()
    prev = old.get(n)
    version = prev["version"] if prev and prev.get("sha256") == sha and prev.get("version") else today
    files.append({"name": n, "version": version, "sha256": sha, "size": len(data)})
with open(path, "w", encoding="utf-8", newline="\n") as f:
    json.dump({"generated": today, "files": files}, f, indent=2)
    f.write("\n")
print("wrote %s (%d files)" % (path, len(files)))
PY
