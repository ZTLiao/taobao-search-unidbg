#!/bin/bash
# SecurityGuard unidbg 探针运行器
# 用法: bash tools/probe.sh <stage> [backend] [jvm-args...]
set -e
PROJ="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJ"

# 自动定位 JDK（跨平台：JAVA_HOME > PATH > macOS java_home）
JH=""
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
  JH="$JAVA_HOME"
else
  JAVABIN="$(command -v java 2>/dev/null || true)"
  if [ -n "$JAVABIN" ]; then
    JH="$(dirname "$(dirname "$JAVABIN")")"
  else
    JH="$(/usr/libexec/java_home 2>/dev/null || true)"
  fi
fi
[ -z "$JH" ] || [ ! -x "$JH/bin/java" ] && { echo "NO JDK FOUND"; exit 1; }

# classpath 分隔符：Windows(Git Bash/MINGW) 用 ';'，其余用 ':'
SEP=":"
case "$(uname -s 2>/dev/null)" in MINGW*|MSYS*|CYGWIN*) SEP=";" ;; esac
CP="$PROJ/target/classes$SEP$PROJ/target/test-classes$SEP$(cat "$PROJ/target/cp.txt")"
STAGE="${1:-onLoad}"
BACKEND="${2:-unicorn}"
exec "$JH/bin/java" -Xmx3g -cp "$CP" \
  -Djna.tmpdir="${TMPDIR:-/tmp}/unidbg-jna" \
  com.taobao.search.probe.SgProbe "$STAGE" "$BACKEND"
