#!/usr/bin/env bash
# 图片搜索真实上传测试：从网上下载的手机图片 -> imagePath / imageBase64 上传 -> mock 网关。
# 验证：1) 图片 base64 真正进入 strimg 参数（网关日志实证）
#       2) 图片搜索接口返回成功 + 识别结果
# 用法: bash tools/test_image_upload.sh [图片路径]
set -u
PROJ="$(cd "$(dirname "$0")/.." && pwd)"
IMG="${1:-/tmp/tb_img/phone.jpg}"

JAVA_BIN=""
if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then JAVA_BIN="$JAVA_HOME/bin/java"
else JAVA_BIN="$(command -v java || true)"; fi
[ -z "$JAVA_BIN" ] && { echo "ERROR: 找不到 java" >&2; exit 1; }
[ -f "$IMG" ] || { echo "ERROR: 图片不存在 $IMG" >&2; exit 1; }

GW_PORT="${GW_PORT:-8099}"
APP_PORT="${APP_PORT:-9092}"
JAR="$PROJ/target/taobao-search-unidbg-1.0.0.jar"
GW_LOG=/tmp/tb_img_gw.log
APP_LOG=/tmp/tb_img_app.log

cleanup() {
  [ -n "${APP_PID:-}" ] && kill "$APP_PID" 2>/dev/null
  [ -n "${GW_PID:-}" ] && kill "$GW_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT INT TERM

echo "===== 0) 测试图片 ====="
file "$IMG"; ls -la "$IMG"

echo "===== 1) mock 网关 (:$GW_PORT) ====="
python3 "$PROJ/tools/mock_gateway.py" "$GW_PORT" > "$GW_LOG" 2>&1 &
GW_PID=$!

echo "===== 2) SpringBoot (:$APP_PORT) ====="
cd "$PROJ"
"$JAVA_BIN" -jar "$JAR" \
  --server.port="$APP_PORT" \
  --mtop.gateway="http://127.0.0.1:$GW_PORT/" \
  --search.sign-backend=h5 > "$APP_LOG" 2>&1 &
APP_PID=$!

READY=0
for i in $(seq 1 45); do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 \
    "http://127.0.0.1:$APP_PORT/api/health" 2>/dev/null)
  [ "$code" = "200" ] && { echo "服务就绪 (${i}s)"; READY=1; break; }
  sleep 1
done
[ "$READY" = "1" ] || { echo "服务未就绪"; tail -30 "$APP_LOG"; exit 1; }

IMG_B64=$(base64 < "$IMG" | tr -d '\n')

echo
echo "===== 3) 图片搜索 · imagePath（本地文件转 base64 上传）====="
PATH_JSON=$(curl -s --max-time 60 -X POST "http://127.0.0.1:$APP_PORT/api/image_search/path" \
  -H 'Content-Type: application/json' \
  -d "{\"imagePath\":\"$IMG\",\"human\":false}")
echo "$PATH_JSON" | python3 -c 'import sys,json; d=json.load(sys.stdin); d["requestUrl"]="<省略含 base64 的 URL>"; print(json.dumps(d,ensure_ascii=False))'

echo
echo "===== 4) 图片搜索 · imageBase64（data: 前缀 + 直传）====="
B64_JSON=$(curl -s --max-time 60 -X POST "http://127.0.0.1:$APP_PORT/api/image_search" \
  -H 'Content-Type: application/json' \
  -d "{\"imageBase64\":\"data:image/jpeg;base64,$IMG_B64\",\"human\":false}")
echo "$B64_JSON" | python3 -c 'import sys,json; d=json.load(sys.stdin); d["signMeta"]=d.get("signMeta"); print(json.dumps(d,ensure_ascii=False)[:400])'

echo
echo "===== 5) 网关上传实证日志 ====="
grep "IMAGE" "$GW_LOG"

echo
echo "===== 6) 断言 ====="
printf '%s\n%s\n' "$PATH_JSON" "$B64_JSON" | python3 -c '
import sys, json
lines=[l for l in sys.stdin.read().splitlines() if l.strip()]
assert len(lines)==2, "需要 2 个响应，实际 %d" % len(lines)
ok=True
for name,line in zip(["imagePath", "imageBase64"], lines):
    try: r=json.loads(line)
    except Exception as e:
        print("FAIL %-12s 非 JSON: %s"%(name,e)); ok=False; continue
    good=(r.get("success") is True and r.get("gatewayRet")=="SUCCESS"
          and isinstance(r.get("items"),list) and len(r["items"])>0)
    print("%s %-12s success=%s gatewayRet=%s items=%s" % (
        "PASS" if good else "FAIL", name, r.get("success"), r.get("gatewayRet"),
        len(r.get("items") or [])))
    ok &= good
print("IMAGE_UPLOAD_RESULT=" + ("PASS" if ok else "FAIL"))
sys.exit(0 if ok else 1)
'
ASSERT_RC=$?

echo
echo "===== 网关统计 ====="
curl -s "http://127.0.0.1:$GW_PORT/"; echo
exit "$ASSERT_RC"
