#!/usr/bin/env bash
# 端到端回归：免登录文本搜索静态兜底 CDN（watchcat）
#
# 覆盖两层：
#   1) WatchcatRegression 独立探针 —— URL 的 MD5 向量、回退契约、真实商品矩阵
#   2) 真实 SpringBoot HTTP API —— /api/search 在 watchcat 协议下返回真实商品
#
# 用法: bash tools/e2e_watchcat.sh
#   依赖: 已 package 出 target/taobao-search-unidbg-1.0.0.jar（脚本会自动 compile）
#   端口: 默认 9097（避开手动演示用的 9096），可用 WATCHCAT_APP_PORT 覆盖
set -u

PROJ="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJ"

JAVA_BIN=""
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
  JAVA_BIN="$JAVA_HOME/bin/java"
else
  JAVA_BIN="$(command -v java || true)"
fi
if [ -z "$JAVA_BIN" ]; then
  echo "ERROR: 找不到可用的 java" >&2; exit 1
fi
echo "使用 JDK: $JAVA_BIN"

JAR="$PROJ/target/taobao-search-unidbg-1.0.0.jar"
APP_PORT="${WATCHCAT_APP_PORT:-9097}"
APP_LOG="$PROJ/target/e2e_watchcat_app.log"
CP_FILE="$PROJ/target/cp.txt"

if [ ! -f "$JAR" ]; then
  echo "ERROR: 未找到 $JAR，请先执行 mvn package" >&2; exit 1
fi

cleanup() {
  [ -n "${APP_PID:-}" ] && kill "$APP_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT INT TERM

echo
echo "===== 1) 编译 + 运行独立探针 WatchcatRegression ====="
if [ ! -s "$CP_FILE" ]; then
  echo "生成 dependency classpath ..."
  mvn -q dependency:build-classpath -Dmdep.outputFile="$CP_FILE"
fi
mvn -q -DskipTests compile || { echo "ERROR: mvn compile 失败" >&2; exit 1; }
CP="$(cat "$CP_FILE")"
mkdir -p target/test-classes
javac -encoding UTF-8 -cp "target/classes;$CP" \
  -d target/test-classes src/test/java/com/taobao/search/probe/WatchcatRegression.java \
  || { echo "ERROR: javac 探针失败" >&2; exit 1; }
java -cp "target/classes;target/test-classes;$CP" com.taobao.search.probe.WatchcatRegression
PROBE_RC=$?
echo "PROBE_RC=$PROBE_RC"

echo
echo "===== 2) 启动 SpringBoot (:$APP_PORT, mtop.protocol=watchcat) ====="
"$JAVA_BIN" -jar "$JAR" \
  --server.port="$APP_PORT" \
  --mtop.protocol=watchcat \
  --unidbg.enabled=false \
  --search.watchcat.enabled=true \
  > "$APP_LOG" 2>&1 &
APP_PID=$!

READY=0
for i in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    "http://127.0.0.1:$APP_PORT/api/health" 2>/dev/null)
  [ "$code" = "200" ] && { echo "服务就绪 (${i}s)"; READY=1; break; }
  sleep 1
done
if [ "$READY" != "1" ]; then
  echo "ERROR: 服务未就绪，日志尾部：" >&2; tail -40 "$APP_LOG" >&2; exit 1
fi

echo
echo "===== 3) health ====="
curl -s "http://127.0.0.1:$APP_PORT/api/health"; echo

echo
echo "===== 4) 真实 HTTP API 搜索矩阵 ====="
R1=$(curl -s --max-time 30 -X POST "http://127.0.0.1:$APP_PORT/api/search" \
  -H 'Content-Type: application/json' -d '{"q":"iphone18","page":1,"human":false}')
R2=$(curl -s --max-time 30 -X POST "http://127.0.0.1:$APP_PORT/api/search" \
  -H 'Content-Type: application/json' -d '{"q":"iphone18","page":2,"human":false}')
R3=$(curl -s --max-time 30 -X POST "http://127.0.0.1:$APP_PORT/api/search" \
  -H 'Content-Type: application/json' -d '{"q":"连衣裙","page":1,"human":false}')

printf '%s\n%s\n%s\n' "$R1" "$R2" "$R3" | python3 -c '
import sys, json
lines = [l for l in sys.stdin.read().splitlines() if l.strip()]
cases = [("iphone18/p1", "iphone181"), ("iphone18/p2", "iphone182"), ("连衣裙/p1", "连衣裙1")]
assert len(lines) == 3, "需要 3 个接口响应，实际 %d" % len(lines)
ok = True
for (name, key), line in zip(cases, lines):
    try:
        r = json.loads(line)
    except Exception as e:
        print("FAIL %-14s 非 JSON: %s" % (name, e)); ok = False; continue
    meta = r.get("signMeta") or {}
    items = r.get("items") or []
    first = items[0] if items else {}
    good = (r.get("success") is True
            and r.get("gatewayRet") == "SUCCESS"
            and r.get("signBackend") == "watchcat-static-cdn"
            and "静态兜底CDN" in (r.get("ret") or "")
            and len(items) > 0
            and bool(first.get("title"))
            and meta.get("_watchcat") == "enabled"
            and meta.get("_watchcat_key") == "66_30.4" + key
            and str(meta.get("_watchcat_url", "")).endswith(".json"))
    print("%s %-14s success=%s ret=%s backend=%s items=%d key=%s" % (
        "PASS" if good else "FAIL", name, r.get("success"), r.get("ret"),
        r.get("signBackend"), len(items), meta.get("_watchcat_key")))
    if good:
        print("      top1: %s | ¥%s" % (first.get("title"), first.get("price")))
    else:
        print("      raw: %s" % line[:400])
    if not good: ok = False
print("HTTP_ASSERT=" + ("PASS" if ok else "FAIL"))
sys.exit(0 if ok else 1)
'
HTTP_RC=$?

echo
echo "===== 5) 汇总 ====="
echo "PROBE_RC=$PROBE_RC  HTTP_RC=$HTTP_RC"
if [ "$PROBE_RC" = "0" ] && [ "$HTTP_RC" = "0" ]; then
  echo "E2E_WATCHCAT_RESULT=PASS"
  exit 0
else
  echo "E2E_WATCHCAT_RESULT=FAIL"
  echo "---- app log tail ----"
  tail -30 "$APP_LOG"
  exit 1
fi
