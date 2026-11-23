#!/usr/bin/env bash
# 免登录原生搜索端到端回归：bridge + SpringBoot(native) + 文本/图片搜索
# 用法: bash tools/e2e_native.sh
set -u
cd "$(dirname "$0")/.."
PORT_APP=9094
PORT_BRIDGE=9091
# 跨平台探测（macOS / Windows Git Bash / Linux），不再写死某台机器的路径
PY="$(command -v python3 || true)"
if [ -z "$PY" ]; then echo "ERROR: python3 不可用" >&2; exit 1; fi
if [ -z "${JAVA_HOME:-}" ] || [ ! -x "$JAVA_HOME/bin/java" ]; then
  for CAND in "/c/Program Files/Java/jdk-1.8" \
              "/Users/liaozetao/Library/Java/JavaVirtualMachines/corretto-1.8.0_452/Contents/Home"; do
    if [ -x "$CAND/bin/java" ]; then export JAVA_HOME="$CAND"; break; fi
  done
fi
JAR=target/taobao-search-unidbg-1.0.0.jar
JAVA_BIN="${JAVA_HOME:+$JAVA_HOME/bin/java}"
if [ -z "$JAVA_BIN" ] || [ ! -x "$JAVA_BIN" ]; then JAVA_BIN="$(command -v java || true)"; fi
if [ -z "$JAVA_BIN" ]; then echo "ERROR: java 不可用" >&2; exit 1; fi

echo "=== [0] 环境检查（不杀已有进程，端口占用时复用）==="
echo "python3=$PY java=$JAVA_BIN"
bash tools/preflight_device.sh "$PORT_BRIDGE" || true

echo "=== [1] 启动 bridge ==="
nohup "$PY" tools/frida_rpc_bridge.py --port "$PORT_BRIDGE" > /tmp/e2e_bridge.log 2>&1 &
BRIDGE_PID=$!
for i in $(seq 1 20); do
  curl -s -m 2 "http://127.0.0.1:$PORT_BRIDGE/health" >/dev/null 2>&1 && break
  sleep 1
done
echo "bridge health: $(curl -s -m 3 http://127.0.0.1:$PORT_BRIDGE/health | head -c 40)"

echo "=== [2] 启动 SpringBoot native 模式 ==="
nohup "$JAVA_BIN" -jar "$JAR" \
  --server.port=$PORT_APP \
  --mtop.protocol=native \
  --sign.rpc.native-search-url=http://127.0.0.1:$PORT_BRIDGE/api/search/native \
  > /tmp/e2e_app.log 2>&1 &
APP_PID=$!
for i in $(seq 1 25); do
  curl -s -m 2 "http://127.0.0.1:$PORT_APP/api/health" >/dev/null 2>&1 && break
  sleep 1
done
echo "app health: $(curl -s -m 3 http://127.0.0.1:$PORT_APP/api/health | head -c 40)"
echo "bridge health: $(curl -s -m 3 http://127.0.0.1:$PORT_BRIDGE/health | head -c 30)"

echo "=== [3] 原生文本搜索 (iphone17) ==="
curl -s -m 60 -X POST "http://127.0.0.1:$PORT_APP/api/search" \
  -H 'Content-Type: application/json' \
  -d '{"q":"iphone17","page":1,"pageSize":20}' | \
  "$PY" -c "import sys,json; d=json.load(sys.stdin); print(json.dumps({k:d.get(k) for k in ['success','api','ret','signBackend','gatewayRet','tokenState','signMeta']},ensure_ascii=False))"
echo "bridge after text: $(curl -s -m 3 http://127.0.0.1:$PORT_BRIDGE/health | head -c 25)"

echo "=== [4] 原生图片搜索 (iphone18) ==="
curl -s -m 90 -X POST "http://127.0.0.1:$PORT_APP/api/image_search/path" \
  -H 'Content-Type: application/json' \
  -d '{"imagePath":"/tmp/tb_img/iphone18_tiny.jpg"}' | \
  "$PY" -c "import sys,json; d=json.load(sys.stdin); print(json.dumps({k:d.get(k) for k in ['success','api','ret','signBackend','gatewayRet','tokenState','signMeta']},ensure_ascii=False))"
echo "bridge after image: $(curl -s -m 3 http://127.0.0.1:$PORT_BRIDGE/health | head -c 25)"

echo "=== [5] 稳定性：连续3次文本 ==="
for i in 1 2 3; do
  curl -s -m 60 -X POST "http://127.0.0.1:$PORT_APP/api/search" \
    -H 'Content-Type: application/json' -d '{"q":"iphone17"}' | \
    "$PY" -c "import sys,json; d=json.load(sys.stdin); print('  call ret=',d.get('ret'),'backend=',d.get('signBackend'))" 2>&1 | head -1
done
echo "bridge final: $(curl -s -m 3 http://127.0.0.1:$PORT_BRIDGE/health | head -c 25)"

echo "=== [6] 日志摘要 ==="
echo "-- bridge --"; tail -8 /tmp/e2e_bridge.log
echo "-- app errors --"; grep -iE "原生搜索失败|exception|error" /tmp/e2e_app.log | tail -5 || true

# 保留服务运行，便于人工复测
echo "=== 完成 (bridge=$BRIDGE_PID app=$APP_PID 保留运行) ==="
