#!/usr/bin/env bash
# 淘宝免登录原生栈搜索：设备预检（只读，不改动设备/账号）
#
# 用途：在跑 native 协议搜索前，确认设备条件满足「游客态 + App 原生 anetwork 栈」验证前提。
# 依据：docs/HOOK_GUIDE.md 第 13-18 章
#   - qemu 模拟器：UC WebView 不支持，搜索结果页黑屏（NOT_SUPPORT_ARCH:qemu）
#   - userdebug/已 root 的 GSI：AuthSDK 600005，登录/搜索组件被拒，容易进入风控冷却
#   - frida bridge 必须 attach 到 com.taobao.taobao 主进程
#
# 用法: bash tools/preflight_device.sh [bridge端口，默认9091]
set -u

BRIDGE_PORT="${1:-9091}"
FAIL=0
WARN=0
ok()   { printf '  [OK]   %s\n' "$1"; }
warn() { printf '  [WARN] %s\n' "$1"; WARN=$((WARN + 1)); }
bad()  { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL + 1)); }

echo "=== 淘宝免登录原生栈：设备预检 ==="

# 0) 本机工具
if command -v adb >/dev/null 2>&1; then ok "adb 可用"; else bad "adb 不可用，请把 Android SDK platform-tools 加入 PATH"; fi
if command -v python3 >/dev/null 2>&1; then ok "python3 可用"; else bad "python3 不可用"; fi
if command -v frida >/dev/null 2>&1; then ok "frida CLI 可用 ($(frida --version 2>/dev/null))"; else warn "本机 frida CLI 未找到（bridge 可能仍能工作）"; fi

# 1) 设备连接
DEV="$(adb devices 2>/dev/null | awk 'NR>1 && $2=="device" {print $1; exit}')"
if [ -z "$DEV" ]; then
  bad "没有已授权的 Android 设备（adb devices 为空）"
  DEV=""
else
  ok "设备: $DEV"
fi

if [ -n "$DEV" ]; then
  # 2) 是否模拟器（qemu 上搜索页必黑屏）
  QEMU="$(adb -s "$DEV" shell getprop ro.kernel.qemu 2>/dev/null | tr -d '\r\n')"
  if [ "$QEMU" = "1" ]; then
    bad "当前是 qemu 模拟器：UC WebView 不支持，搜索结果页会黑屏，无法完成真机验证"
  else
    ok "非 qemu 环境 (ro.kernel.qemu='${QEMU:-空}')"
  fi

  # 3) root / userdebug 风险
  ROOT_ID="$(adb -s "$DEV" shell id 2>/dev/null | tr -d '\r\n')"
  case "$ROOT_ID" in
    uid=0*) warn "adb 以 root 运行：AuthSDK 可能报 600005 并拒绝搜索/登录组件" ;;
    *) ok "adb shell 非 root ($ROOT_ID)" ;;
  esac
  SU="$(adb -s "$DEV" shell 'ls /system/xbin/su /system/bin/su /sbin/su 2>/dev/null' 2>/dev/null | tr -d '\r\n')"
  if [ -n "$SU" ]; then
    warn "系统内存在 su（userdebug GSI 常见）：淘宝 AuthSDK 600005 会拒绝登录态，游客态也易被风控"
  else
    ok "未发现系统 su"
  fi

  # 4) 淘宝是否安装 / 是否在前台
  if adb -s "$DEV" shell pm list packages com.taobao.taobao 2>/dev/null | grep -q 'com.taobao.taobao'; then
    ok "淘宝已安装"
  else
    bad "淘宝未安装，请先安装原版 10.69.x（反编译重打包版仅供研究，不建议用于真机验证）"
  fi
  FOCUS="$(adb -s "$DEV" shell dumpsys activity activities 2>/dev/null | grep -m1 -i 'mResumedActivity' || true)"
  if echo "$FOCUS" | grep -q 'com.taobao.taobao'; then
    ok "淘宝处于前台"
  else
    warn "淘宝不在前台（${FOCUS:-读取失败}）：建议先手动打开 App 浏览首页商品流做预热"
  fi
  FRIDA_PS="$(adb -s "$DEV" shell ps -A 2>/dev/null | grep -i 'frida-server' | grep -v grep || true)"
  if [ -n "$FRIDA_PS" ]; then ok "frida-server 正在运行"; else warn "设备端未发现 frida-server，bridge 将无法 attach"; fi
fi

# 5) bridge 健康状态
if curl -s -m 3 "http://127.0.0.1:$BRIDGE_PORT/health" >/dev/null 2>&1; then
  ok "frida bridge 健康 (:$(echo "$BRIDGE_PORT"))"
else
  warn "frida bridge 未启动 (:$(echo "$BRIDGE_PORT"))；启动命令："
  echo '     python3 tools/frida_rpc_bridge.py --port '"$BRIDGE_PORT"
fi

echo "=== 结论 ==="
if [ "$FAIL" -gt 0 ]; then
  echo "不具备真机验证条件（$FAIL 项失败，$WARN 项警告）。先解决 FAIL 项。"
elif [ "$WARN" -gt 0 ]; then
  echo "可以运行，但有 $WARN 项警告：建议先预热 App、降低频率，并观察 gatewayRet。"
else
  echo "PASS：设备条件满足游客态原生栈搜索验证。"
fi
exit 0
