#!/usr/bin/env bash
# 免登录原生搜索端到端回归：bridge + SpringBoot(native) + 文本/图片搜索
# 用法: bash tools/e2e_native.sh
set -u
cd "$(dirname "$0")/.."
PORT_APP=9094
PORT_BRIDGE=9091
PY=/Users/liaozetao/.workbuddy/binaries/python/versions/3.13.12/bin/python3
export JAVA_HOME=/Users/liaozetao/Library/Java/JavaVirtualMachines/corretto-1.8.0_452/Contents/Home
JAR=target/taobao-search-unidbg-1.0.0.jar

echo "=== [0] 清理 ==="
pkill -f frida_rpc_bridge 2>/dev/null || true
pkill -f 'taobao-search-unidbg-1.0.0' 2>/dev/null || true
sleep 2

echo "=== [1] 启动 bridge ==="
nohup "$PY" tools/frida_rpc_bridge.py --port "$PORT_BRIDGE" > /tmp/e2e_bridge.log 2>&1 &
BRIDGE_PID=$!
for i in $(seq 1 20); do
  curl -s -m 2 "http://127.0.0.1:$PORT_BRIDGE/health" >/dev/null 2>&1 && break
  sleep 1
done
echo "bridge health: $(curl -s -m 3 http://127.0.0.1:$PORT_BRIDGE/health | head -c 40)"

echo "=== [2] 启动 SpringBoot native 模式 ==="
nohup "$JAVA_HOME/bin/java" -jar "$JAR" \
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
