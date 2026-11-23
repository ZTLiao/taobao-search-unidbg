#!/usr/bin/env bash
# 免登录原生栈搜索：低频、可中止的真机验证封装
#
# 设计目标：用 App 自身 anetwork 栈 + 游客态发请求（docs/HOOK_GUIDE.md 第 17-18 章），
# 一旦命中 bixi 风控（USER_VALIDATE / TRAFFIC_LIMIT / FEC40002）立刻停止，
# 避免高频重试把设备打进 CheckCodeValidate / 账户保护冷却期。
#
# 用法:
#   bash tools/native_search_safe.sh                 # 默认查询 iphone17，最多 3 次，间隔 20s
#   QUERY=连衣裙 MAX_CALLS=2 INTERVAL=30 bash tools/native_search_safe.sh
set -u
cd "$(dirname "$0")/.."
PROJ="$(pwd)"

QUERY="${QUERY:-iphone17}"
MAX_CALLS="${MAX_CALLS:-3}"
INTERVAL="${INTERVAL:-20}"
BRIDGE_PORT="${BRIDGE_PORT:-9091}"
APP_PORT="${APP_PORT:-9094}"
JAR="$PROJ/target/taobao-search-unidbg-1.0.0.jar"

# 允许用 PYTHON_BIN 指定带 frida 模块的解释器（本环境 python3 指向 3.13 无 frida）
PY="${PYTHON_BIN:-$(command -v python3 || true)}"
if [ -z "$PY" ]; then echo "ERROR: python3 不可用（可设置 PYTHON_BIN）" >&2; exit 1; fi

JAVA_BIN=""
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
  JAVA_BIN="$JAVA_HOME/bin/java"
elif [ -x "/c/Program Files/Java/jdk-1.8/bin/java" ]; then
  JAVA_BIN="/c/Program Files/Java/jdk-1.8/bin/java"
elif [ -x "/Users/liaozetao/Library/Java/JavaVirtualMachines/corretto-1.8.0_452/Contents/Home/bin/java" ]; then
  JAVA_BIN="/Users/liaozetao/Library/Java/JavaVirtualMachines/corretto-1.8.0_452/Contents/Home/bin/java"
else
  JAVA_BIN="$(command -v java || true)"
fi
if [ -z "$JAVA_BIN" ] || [ ! -f "$JAR" ]; then
  echo "ERROR: 需要 java 与 $JAR（先执行 mvn package）" >&2; exit 1
fi

echo "===== 0) 设备预检 ====="
bash "$PROJ/tools/preflight_device.sh" "$BRIDGE_PORT"
echo

echo "===== 1) 确保 frida bridge 可用 ====="
BRIDGE_PID=""
if ! curl -s -m 3 "http://127.0.0.1:$BRIDGE_PORT/health" >/dev/null 2>&1; then
  nohup "$PY" "$PROJ/tools/frida_rpc_bridge.py" --port "$BRIDGE_PORT" \
    > "$PROJ/bridge_safe.log" 2>&1 &
  BRIDGE_PID=$!
  for i in $(seq 1 20); do
    curl -s -m 2 "http://127.0.0.1:$BRIDGE_PORT/health" >/dev/null 2>&1 && break
    sleep 1
  done
fi
if ! curl -s -m 3 "http://127.0.0.1:$BRIDGE_PORT/health" >/dev/null 2>&1; then
  echo "ERROR: bridge 启动失败，查看 bridge_safe.log；常见原因是未连接设备或 frida-server 未运行" >&2
  [ -n "$BRIDGE_PID" ] && kill "$BRIDGE_PID" 2>/dev/null || true
  exit 1
fi
echo "bridge health: $(curl -s -m 3 "http://127.0.0.1:$BRIDGE_PORT/health" | head -c 120)"

echo "===== 2) 确保 SpringBoot native 模式可用 ====="
APP_PID=""
if ! curl -s -m 3 "http://127.0.0.1:$APP_PORT/api/health" >/dev/null 2>&1; then
  nohup "$JAVA_BIN" -jar "$JAR" \
    --server.port="$APP_PORT" \
    --mtop.protocol=native \
    --sign.rpc.native-search-url="http://127.0.0.1:$BRIDGE_PORT/api/search/native" \
    > "$PROJ/app_safe.log" 2>&1 &
  APP_PID=$!
  for i in $(seq 1 30); do
    curl -s -m 2 "http://127.0.0.1:$APP_PORT/api/health" >/dev/null 2>&1 && break
    sleep 1
  done
fi
if ! curl -s -m 3 "http://127.0.0.1:$APP_PORT/api/health" >/dev/null 2>&1; then
  echo "ERROR: 服务启动失败，查看 app_safe.log" >&2
  [ -n "$APP_PID" ] && kill "$APP_PID" 2>/dev/null || true
  [ -n "$BRIDGE_PID" ] && kill "$BRIDGE_PID" 2>/dev/null || true
  exit 1
fi
echo "app health: $(curl -s -m 3 "http://127.0.0.1:$APP_PORT/api/health" | head -c 120)"

echo "===== 3) 低频搜索（最多 $MAX_CALLS 次，间隔 ${INTERVAL}s）====="
STOP=0
for i in $(seq 1 "$MAX_CALLS"); do
  echo "--- call #$i q=$QUERY ---"
  RESP="$(curl -s -m 90 -X POST "http://127.0.0.1:$APP_PORT/api/search" \
    -H 'Content-Type: application/json' \
    -d "{\"q\":\"$QUERY\",\"page\":1,\"pageSize\":20,\"human\":true}")"
  echo "$RESP" > "$PROJ/native_search_safe_last.json"
  echo "$RESP" | "$PY" -c '
import sys, json
try:
    d = json.load(sys.stdin)
    print(json.dumps({k: d.get(k) for k in ["success","ret","gatewayRet","signBackend","tokenState","attempts","hint","items"]}, ensure_ascii=False)[:1200])
except Exception as e:
    print("解析失败:", e)
' 2>/dev/null
  if echo "$RESP" | grep -Eq 'RISK_CONTROL|USER_VALIDATE|TRAFFIC_LIMIT|FEC40002|ANTI_ATTACK'; then
    echo "命中服务端风控/冷却：立即停止后续请求，避免账户/设备进入保护页。"
    STOP=1
    break
  fi
  if [ "$i" -lt "$MAX_CALLS" ]; then sleep "$INTERVAL"; fi
done

echo "===== 4) 收尾 ====="
if [ "$STOP" -eq 0 ]; then echo "未命中风控，已执行 $MAX_CALLS 次。"; fi
echo "最后响应: $PROJ/native_search_safe_last.json"
# 只清理本脚本自己启动的进程；外部已运行的 bridge/app 保留
[ -n "$APP_PID" ] && kill "$APP_PID" 2>/dev/null && echo "stopped app pid=$APP_PID"
[ -n "$BRIDGE_PID" ] && kill "$BRIDGE_PID" 2>/dev/null && echo "stopped bridge pid=$BRIDGE_PID"
exit 0
