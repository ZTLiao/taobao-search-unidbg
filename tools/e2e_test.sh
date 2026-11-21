#!/usr/bin/env bash
# 端到端验证：本地 mock 网关 + 模拟签名服务，证明
#   1) h5 后端「自动获取 token -> 重算 sign -> 重试 -> 成功解析」握手闭环
#   2) rpc 后端「请求编排 -> 外部签名服务 -> 网关」可插拔签名源通路
# 用法: bash tools/e2e_test.sh   （需先 mvn package）
set -u

PROJ="$(cd "$(dirname "$0")/.." && pwd)"

# 不轻信外部 JAVA_HOME（可能指向不存在的 JDK），按可用性探测
DEFAULT_JH=/Users/liaozetao/Library/Java/JavaVirtualMachines/corretto-1.8.0_452/Contents/HOME
JAVA_BIN=""
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
  JAVA_BIN="$JAVA_HOME/bin/java"
elif [ -x "$DEFAULT_JH/bin/java" ]; then
  JAVA_BIN="$DEFAULT_JH/bin/java"
else
  JAVA_BIN="$(command -v java || true)"
fi
if [ -z "$JAVA_BIN" ]; then
  echo "ERROR: 找不到可用的 java" >&2
  exit 1
fi
echo "使用 JDK: $JAVA_BIN"

GW_PORT="${GW_PORT:-8099}"
RPC_PORT="${RPC_PORT:-8098}"
APP_PORT="${APP_PORT:-9090}"
JAR="$PROJ/target/taobao-search-unidbg-1.0.0.jar"
GW_LOG=/tmp/tb_mock_gw.log
RPC_LOG=/tmp/tb_mock_sign_rpc.log
APP_LOG=/tmp/tb_app.log

if [ ! -f "$JAR" ]; then
  echo "ERROR: 未找到 $JAR，请先执行 mvn package" >&2
  exit 1
fi

cleanup() {
  [ -n "${APP_PID:-}" ] && kill "$APP_PID" 2>/dev/null
  [ -n "${GW_PID:-}" ] && kill "$GW_PID" 2>/dev/null
  [ -n "${RPC_PID:-}" ] && kill "$RPC_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT INT TERM

echo "===== 1) 启动本地 mock MTOP 网关 (:$GW_PORT) ====="
python3 "$PROJ/tools/mock_gateway.py" "$GW_PORT" > "$GW_LOG" 2>&1 &
GW_PID=$!

echo "===== 2) 启动模拟签名服务 (:$RPC_PORT, stand-in for unidbg-server) ====="
python3 "$PROJ/tools/mock_sign_rpc.py" "$RPC_PORT" > "$RPC_LOG" 2>&1 &
RPC_PID=$!

echo "===== 3) 启动 SpringBoot 服务 (:$APP_PORT, backend=h5/rpc, gateway=local) ====="
"$JAVA_BIN" -jar "$JAR" \
  --server.port="$APP_PORT" \
  --mtop.gateway="http://127.0.0.1:$GW_PORT/" \
  --sign.rpc.url="http://127.0.0.1:$RPC_PORT/api/sign" \
  --search.sign-backend=h5 > "$APP_LOG" 2>&1 &
APP_PID=$!

for i in $(seq 1 45); do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    "http://127.0.0.1:$APP_PORT/api/health" 2>/dev/null)
  [ "$code" = "200" ] && { echo "服务就绪 (${i}s)"; break; }
  sleep 1
done

echo
echo "===== 4) health ====="
curl -s "http://127.0.0.1:$APP_PORT/api/health"; echo

echo
echo "===== 5) 主动握手 /api/token/handshake ====="
curl -s -X POST "http://127.0.0.1:$APP_PORT/api/token/handshake" \
  -H 'Content-Type: application/json' -d '{"q":"连衣裙"}'; echo

echo
echo "===== 6) 文本搜索 /api/search (backend=h5) ====="
SEARCH_JSON=$(curl -s -X POST "http://127.0.0.1:$APP_PORT/api/search" \
  -H 'Content-Type: application/json' -d '{"q":"连衣裙","page":1,"human":false}')
echo "$SEARCH_JSON"

echo
echo "===== 7) 联想词 /api/suggest ====="
SUGGEST_JSON=$(curl -s "http://127.0.0.1:$APP_PORT/api/suggest?q=%E8%BF%9E%E8%A1%A3%E8%A3%99&human=false")
echo "$SUGGEST_JSON"

echo
echo "===== 8) 图片搜索 /api/image_search ====="
IMAGE_JSON=$(curl -s -X POST "http://127.0.0.1:$APP_PORT/api/image_search" \
  -H 'Content-Type: application/json' \
  -d '{"imageUrl":"https://img.example.com/a.jpg","human":false}')
echo "$IMAGE_JSON"

echo
echo "===== 9) 外部签名服务通路 /api/search (backend=rpc) ====="
RPC_JSON=$(curl -s -X POST "http://127.0.0.1:$APP_PORT/api/search" \
  -H 'Content-Type: application/json' \
  -d '{"q":"连衣裙","signBackend":"rpc","human":false}')
echo "$RPC_JSON"

echo
echo "===== 10) 断言 ====="
printf '%s\n%s\n%s\n%s\n' "$SEARCH_JSON" "$SUGGEST_JSON" "$IMAGE_JSON" "$RPC_JSON" | python3 -c '
import sys, json
lines = [l for l in sys.stdin.read().splitlines() if l.strip()]
names = ["text_search", "suggest", "image_search", "rpc_search"]
assert len(lines) == 4, "需要 4 个接口响应，实际 %d" % len(lines)
ok = True
for name, line in zip(names, lines):
    try:
        r = json.loads(line)
    except Exception as e:
        print("FAIL %-14s 非 JSON: %s" % (name, e)); ok = False; continue
    common = (r.get("success") is True
              and r.get("gatewayRet") == "SUCCESS"
              and r.get("tokenState") in ("handshake", "injected")
              and r.get("attempts", 0) >= 1)
    raw = r.get("rawData") or {}
    if name == "suggest":
        # 联想接口返回 suggestList（字符串数组），业务数据在 rawData，不产生 items
        good = common and len(raw) > 0 and len(raw.get("suggestList") or []) > 0
        payload = "suggestList=%d" % len(raw.get("suggestList") or [])
    else:
        good = common and isinstance(r.get("items"), list) and len(r["items"]) > 0
        payload = "items=%d" % len(r.get("items") or [])
    if name == "rpc_search":
        good = good and r.get("signBackend") == "rpc" \
               and "_rpc" in (r.get("signMeta") or {})
        payload += " backend=%s" % r.get("signBackend")
    print("%s %-14s success=%s gatewayRet=%s tokenState=%s attempts=%s %s" % (
        "PASS" if good else "FAIL", name, r.get("success"), r.get("gatewayRet"),
        r.get("tokenState"), r.get("attempts"), payload))
    if r.get("handshakeTrail"):
        for t in r["handshakeTrail"]:
            print("      trail: %s" % t)
    if not good: ok = False
print("E2E_RESULT=" + ("PASS" if ok else "FAIL"))
sys.exit(0 if ok else 1)
'
ASSERT_RC=$?

echo
echo "===== mock 网关握手日志 ====="
cat "$GW_LOG"
echo
echo "===== 模拟签名服务日志 ====="
cat "$RPC_LOG"

echo
echo "===== 网关统计 ====="
curl -s "http://127.0.0.1:$GW_PORT/"; echo

exit "$ASSERT_RC"
