#!/usr/bin/env bash
# ============================================================
# 正面破解 SecurityGuard 1927 —— 启动期注入部署脚本
#
# 原理：重打包 APK 自签名 → SG 启动初始化时用「当前 APK 签名」解密
#   yw_1222.jpg 安全图片失败 → SecException 1927 → authCode=null →
#   所有 MTOP 签名失败 (EC40002)。
#   实测证明：签名校验/缓存发生在进程启动早期，attach 后 hook getPackageInfo
#   命中数为 0（签名结果已缓存）。因此必须用 gadget script-directory 模式，
#   在 System.loadLibrary 那一刻就装上 hook，让 SG 读到官方证书。
#
# 前提：
#   1. 重打包 APK 的 gadget config 已改为 script-directory 模式
#      path=/data/local/tmp/frida-scripts, on_change=reload
#   2. 已全量重建并安装该 APK（gradlew clean assembleRelease）
#
# 用法：bash tools/deploy_sg_spoof.sh [设备serial]
# ============================================================
set -e
ADB="${ADB:-C:/Users/pc/rea-tools/platform-tools/adb.exe}"
DEV="${1:-$("${ADB}" devices 2>/dev/null | awk '/device$/{print $1; exit}')}"
SCRIPT_DIR=/data/local/tmp/frida-scripts
PROJECT="C:/Users/pc/IdeaProjects/taobao-search-unidbg"

if [ -z "$DEV" ]; then
  echo "ERROR: 没有在线设备"; exit 1
fi
echo "设备: $DEV"

echo "[1/5] 生成 spoof 脚本并打包 bridge bundle"
python3 "$PROJECT/tools/frida/gen_sg_sigspoof.py"
python3 "$PROJECT/tools/frida/build_rpc_bundle.py" >/dev/null

echo "[2/5] 创建设备端脚本目录"
"${ADB}" -s "$DEV" shell "mkdir -p $SCRIPT_DIR"

echo "[3/5] push 带 bridge 的 bundle 到脚本目录"
# 关键：Frida script-directory 只加载 .js 扩展名文件（不是 .script！）
# 且 bundle 必须含 Java bridge（Frida 17 不内置）
"${ADB}" -s "$DEV" push "$PROJECT/tools/frida/sg_sigspoof_bundle.js" "$SCRIPT_DIR/sg_sigspoof.js"

echo "[4/5] 强制停止并冷启动淘宝（触发 gadget 启动期加载脚本）"
"${ADB}" -s "$DEV" shell "am force-stop com.taobao.taobao"
sleep 2
"${ADB}" -s "$DEV" shell "monkey -p com.taobao.taobao -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1
sleep 15

echo "[5/5] 抓取验证结果（文件标记 + logcat 双判据）"
echo "--- 文件标记（可靠：script-directory 下 console.log 未必进 logcat）---"
"${ADB}" -s "$DEV" shell "cat /data/local/tmp/sg_spoof_status.txt 2>/dev/null || echo NO_STATUS_FILE"
echo "--- 1927 日志（冷启动后应消失）---"
"${ADB}" -s "$DEV" logcat -d -v brief 2>/dev/null | grep -iE "1927|getUnifiedSign|SecException" | tail -20

echo ""
echo "=== 判定标准 ==="
echo "  [OK] 状态文件出现 INSTALLED + HIT，且不再出现 errorCode 1927"
echo "  [FAIL] NO_STATUS_FILE → gadget 未加载脚本，检查 config(on_change=rescan)/扩展名(.js)"
echo "  [FAIL] 有 INSTALLED/HIT 但仍 1927 → SG 走 native 读签名，需转 native 层破解"
