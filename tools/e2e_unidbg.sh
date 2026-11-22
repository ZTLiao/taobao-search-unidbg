#!/usr/bin/env bash
# unidbg 后端端到端回归：mock MTOP 网关 + 真实 unidbg native 签名后端。
# 覆盖 E2E 主脚本的盲区（主脚本只用 h5/rpc），验证本轮 SignContext 修复后：
#   1) unidbg 后端能驱动签名握手（native 四头 + H5 MD5 sign 叠加）
#   2) 文本搜索 / 图片搜索 走 unidbg 后端全链路成功
#   3) signMeta 含 _native_headers=6（四头 + h5 sign + 计数）
# 用法: bash tools/e2e_unidbg.sh   （需先 mvn package）
set -u
PROJ="$(cd "$(dirname "$0")/.." && pwd)"

DEFAULT_JH=/Users/liaozetao/Library/Java/JavaVirtualMachines/corretto-1.8.0_452/Contents/HOME
JAVA_BIN=""
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
  JAVA_BIN="$JAVA_HOME/bin/java"
elif [ -x "$DEFAULT_JH/bin/java" ]; then
  JAVA_BIN="$DEFAULT_JH/bin/java"
else
  JAVA_BIN="$(command -v java || true)"
fi
[ -z "$JAVA_BIN" ] && { echo "ERROR: 找不到 java" >&2; exit 1; }

GW_PORT="${GW_PORT:-8099}"
APP_PORT="${APP_PORT:-9091}"
JAR="$PROJ/target/taobao-search-unidbg-1.0.0.jar"
GW_LOG=/tmp/tb_und_gw.log
APP_LOG=/tmp/tb_und_app.log

[ -f "$JAR" ] || { echo "ERROR: 未找到 $JAR，先 mvn package" >&2; exit 1; }

cleanup() {
  [ -n "${APP_PID:-}" ] && kill "$APP_PID" 2>/dev/null
  [ -n "${GW_PID:-}" ] && kill "$GW_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT INT TERM

echo "===== 1) mock MTOP 网关 (:$GW_PORT) ====="
python3 "$PROJ/tools/mock_gateway.py" "$GW_PORT" > "$GW_LOG" 2>&1 &
GW_PID=$!

echo "===== 2) SpringBoot (:$APP_PORT, unidbg.enabled=true, backend=unidbg) ====="
cd "$PROJ"
"$JAVA_BIN" -Xmx3g -Djna.tmpdir=/tmp/unidbg-jna -jar "$JAR" \
  --server.port="$APP_PORT" \
  --mtop.gateway="http://127.0.0.1:$GW_PORT/" \
  --unidbg.enabled=true \
  --search.sign-backend=unidbg > "$APP_LOG" 2>&1 &
APP_PID=$!

echo "等待服务就绪（unidbg 首次签名加载 SO 约 25s）..."
READY=0
for i in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    "http://127.0.0.1:$APP_PORT/api/health" 2>/dev/null)
  [ "$code" = "200" ] && { echo "服务就绪 (${i}s)"; READY=1; break; }
  sleep 1
done
[ "$READY" = "1" ] || { echo "服务未就绪，日志："; tail -30 "$APP_LOG"; exit 1; }

echo
echo "===== 3) health ====="
curl -s "http://127.0.0.1:$APP_PORT/api/health"; echo

echo
echo "===== 4) 文本搜索 (backend=unidbg) ====="
TEXT_JSON=$(curl -s --max-time 90 -X POST "http://127.0.0.1:$APP_PORT/api/search" \
  -H 'Content-Type: application/json' \
  -d '{"q":"连衣裙","page":1,"signBackend":"unidbg","human":false}')
echo "$TEXT_JSON"

echo
echo "===== 5) 图片搜索 (backend=unidbg) ====="
IMG_JSON=$(curl -s --max-time 90 -X POST "http://127.0.0.1:$APP_PORT/api/image_search" \
  -H 'Content-Type: application/json' \
  -d '{"imageUrl":"https://img.example.com/a.jpg","signBackend":"unidbg","human":false}')
echo "$IMG_JSON"

echo
echo "===== 6) 断言 ====="
printf '%s\n%s\n' "$TEXT_JSON" "$IMG_JSON" | python3 -c '
import sys, json
lines = [l for l in sys.stdin.read().splitlines() if l.strip()]
names = ["unidbg_text_search", "unidbg_image_search"]
assert len(lines) == 2, "需要 2 个响应，实际 %d" % len(lines)
ok = True
for name, line in zip(names, lines):
    try: r = json.loads(line)
    except Exception as e:
        print("FAIL %-20s 非 JSON: %s" % (name, e)); ok = False; continue
    meta = r.get("signMeta") or {}
    native = meta.get("_native_headers")
    # 加固：必须严格等于 6（四 native 头 + h5 sign + 计数），而非仅"非零"。
    # 头丢失/部分生成时 native=5 也能混过旧断言，这里堵住假阳性。
    good = (r.get("success") is True
            and r.get("gatewayRet") == "SUCCESS"
            and r.get("signBackend") == "unidbg"
            and isinstance(r.get("items"), list) and len(r["items"]) > 0
            and str(native) == "6"
            and "present" in str(meta.get("_h5_sign", "")))
    print("%s %-20s success=%s gatewayRet=%s backend=%s nativeHeaders=%s items=%s" % (
        "PASS" if good else "FAIL", name, r.get("success"), r.get("gatewayRet"),
        r.get("signBackend"), native, len(r.get("items") or [])))
    if not good:
        print("      hint=%s signMeta=%s" % (r.get("hint"), meta))
        ok = False
print("E2E_UNIDBG_RESULT=" + ("PASS" if ok else "FAIL"))
sys.exit(0 if ok else 1)
'
ASSERT_RC=$?

echo
echo "===== 应用日志关键行 ====="
grep -E "unidbg 签名完成|70102 payload|ERROR|Exception" "$APP_LOG" | tail -20

exit "$ASSERT_RC"
