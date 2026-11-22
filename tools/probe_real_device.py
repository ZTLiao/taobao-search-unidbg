#!/usr/bin/env python3
"""
真机签名 ground truth 探针（Frida 17 + USB 真机）。

流程：attach 淘宝主进程 -> 注入 rpc_sign_bundle.js 安装 hook ->
通过 scheme 触发一次搜索 -> 读取 buildParams 返回头 / 网络层头 / 设备身份。

用法：
  python3 tools/probe_real_device.py --serial cb76b262
"""
import argparse
import json
import subprocess
import sys
import time

import frida

ADB = "/Users/liaozetao/.local/android/sdk/platform-tools/adb"
PKG = "com.taobao.taobao"
SEARCH_URL = "taobao://s.taobao.com/search?q=iphone18"


def adb(serial, *args):
    cmd = [ADB, "-s", serial] + list(args)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return (r.stdout or "") + (r.stderr or "")


def call(script, name, *args):
    try:
        return script.exports_sync.__getattr__(name)(*args)
    except Exception as e:
        return json.dumps({"_call_error": str(e)})


def pretty(label, raw):
    print("\n===== %s =====" % label)
    try:
        obj = json.loads(raw) if isinstance(raw, str) else raw
        print(json.dumps(obj, ensure_ascii=False, indent=2))
    except Exception:
        print(raw)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial", default="cb76b262")
    ap.add_argument("--bundle", default="tools/frida/rpc_sign_bundle.js")
    ap.add_argument("--no-trigger", action="store_true", help="不触发搜索，只读现有捕获")
    args = ap.parse_args()

    print("[*] 目标设备:", args.serial)

    # 1. frida 连接
    try:
        dev = frida.get_device(args.serial, timeout=10)
    except Exception as e:
        print("[!] frida 连接失败:", e)
        sys.exit(1)

    with open(args.bundle, "r", encoding="utf-8") as f:
        source = f.read()

    messages = []
    def on_message(msg, data):
        if msg.get("type") == "send":
            messages.append(msg.get("payload"))

    # 2. spawn 模式：force-stop -> spawn 淘宝 -> 注入 hook -> resume -> 触发搜索
    if not args.no_trigger:
        print("[*] force-stop 并以 spawn 模式注入 hook...")
        adb(args.serial, "shell", "am", "force-stop", PKG)
        time.sleep(2)
        try:
            spawned_pid = dev.spawn([PKG])
            print("[*] spawn PID:", spawned_pid)
            session = dev.attach(spawned_pid)
            script = session.create_script(source)
            script.on("message", on_message)
            script.load()
            dev.resume(spawned_pid)
            print("[*] hook 已注入，等待 App 初始化...")
            time.sleep(18)
        except Exception as e:
            print("[!] spawn 失败，退回 attach 模式:", e)
            pids = adb(args.serial, "shell", "pidof", PKG).strip().split()
            session = dev.attach(int(pids[0]))
            script = session.create_script(source)
            script.on("message", on_message)
            script.load()
            time.sleep(2)

        pretty("STATUS(初始)", call(script, "status"))
        print("\n[*] 触发搜索 iphone18...")
        adb(args.serial, "shell", "am", "start", "-a",
            "android.intent.action.VIEW", "-d", SEARCH_URL)
        time.sleep(20)
        print("[*] 当前 PID:", adb(args.serial, "shell", "pidof", PKG).strip())
    else:
        pids = adb(args.serial, "shell", "pidof", PKG).strip().split()
        if not pids:
            print("[!] 淘宝未运行"); sys.exit(1)
        session = dev.attach(int(pids[0]))
        script = session.create_script(source)
        script.on("message", on_message)
        script.load()
        time.sleep(2)

    # 4. 读取 ground truth
    pretty("STATUS(搜索后)", call(script, "status"))
    pretty("BUILD_PARAMS_OUT", call(script, "buildParamsOut"))
    pretty("W4J_MAPS", call(script, "w4jMaps"))
    pretty("REAL_HEADS", call(script, "realHeads"))
    pretty("NET_HEADERS", call(script, "netHeaders"))
    pretty("NET_URL_LOG", call(script, "netUrlLog"))
    pretty("HEADER_CAPTURE", call(script, "headerCapture"))
    pretty("LAST_CAPTURE", call(script, "lastCapture"))
    pretty("DEVICE_INFO", call(script, "deviceInfo"))
    pretty("NATIVE_70102", call(script, "native70102"))

    print("\n===== FRIDA SEND 消息(%d) =====" % len(messages))
    for m in messages[-30:]:
        print(str(m)[:300])

    session.detach()
    print("\n[*] DONE")


if __name__ == "__main__":
    main()
