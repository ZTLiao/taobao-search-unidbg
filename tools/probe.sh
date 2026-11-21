#!/bin/bash
# SecurityGuard unidbg 探针运行器
# 用法: bash tools/probe.sh <stage> [backend] [jvm-args...]
set -e
PROJ="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJ"

# 自动定位 JDK（环境里 JAVA_HOME 可能指向无效路径）
JH=""
for c in \
  "/Users/liaozetao/Library/Java/JavaVirtualMachines/corretto-1.8.0_452/Contents/HOME" \
  "$(/usr/libexec/java_home 2>/dev/null)"; do
  [ -x "$c/bin/java" ] && JH="$c" && break
done
[ -z "$JH" ] && { echo "NO JDK FOUND"; exit 1; }

CP="$PROJ/target/classes:$PROJ/target/test-classes:$(cat "$PROJ/target/cp.txt")"
STAGE="${1:-onLoad}"
BACKEND="${2:-unicorn}"
exec "$JH/bin/java" -Xmx3g -cp "$CP" \
  -Djna.tmpdir=/tmp/unidbg-jna \
  com.taobao.search.probe.SgProbe "$STAGE" "$BACKEND"
