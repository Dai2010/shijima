#!/bin/sh
# 冒烟测试：起一个本地 HTTP 服务与 shijima，验证抓包与过滤。
set -eu

BIN=${BIN:-./shijima}
PORT=${PORT:-18899}
UP=${UP:-18080}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/shijima-test.XXXXXX")
PY=python3

cleanup() {
  [ -n "${PX:-}" ] && kill -INT "$PX" 2>/dev/null || true
  [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

$PY -m http.server "$UP" --bind 127.0.0.1 >/dev/null 2>&1 &
SRV=$!
sleep 0.6

"$BIN" -p "$PORT" -o "$TMP/cap.json" --no-console --rules-file "$TMP/rules.yaml" \
  >"$TMP/log" 2>&1 &
PX=$!
sleep 0.8

curl -fsS -x "http://127.0.0.1:$PORT" "http://127.0.0.1:$UP/" -o /dev/null
kill -INT "$PX"
wait "$PX" 2>/dev/null || true
PX=

$PY - "$TMP/cap.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
kinds = [r["kind"] for r in data]
assert "request" in kinds, kinds
assert "response" in kinds, kinds
resp = [r for r in data if r["kind"] == "response"][0]
assert resp["status"] == 200, resp
assert resp["size"] > 0, resp
print("ok:", len(data), "records, response", resp["status"], resp["size"], "bytes")
PY

# 过滤：deny 命中应返回 403 并记录 blocked
"$BIN" -p "$PORT" -o "$TMP/block.json" --no-console --rules-file "$TMP/rules.yaml" \
  --deny '127.0.0.*' >"$TMP/log2" 2>&1 &
PX=$!
sleep 0.8
CODE=$(curl -s -o /dev/null -w '%{http_code}' -x "http://127.0.0.1:$PORT" "http://127.0.0.1:$UP/" || true)
kill -INT "$PX"
wait "$PX" 2>/dev/null || true
PX=
[ "$CODE" = "403" ] || { echo "expected 403, got $CODE"; exit 1; }
grep -q '"kind":"blocked"' "$TMP/block.json" || { echo "no blocked record"; exit 1; }
echo "ok: filter returns 403 and logs blocked"
