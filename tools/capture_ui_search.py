#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
抓取模拟器/真机 UI 真实文本搜索的完整请求凭证（ground truth）。
流程：attach 淘宝挂 hook -> 等待 -> 后台 adb 在搜索框输入关键词并搜索
      -> dump netHeaders/headerCapture/buildParamsOut/最近 w4j 响应。
用途：对比我们手工构造请求缺了哪些 bixi 凭证（x5sec/cookie/token）。
"""
import json, os, subprocess, threading, time
import frida

ADB = "/Users/liaozetao/.local/android/sdk/platform-tools/adb"
SERIAL = os.environ.get("DEVICE", "emulator-5554")
BUNDLE = os.path.join(os.path.dirname(__file__), "frida", "rpc_sign_bundle.js")
KEYWORD = os.environ.get("KEYWORD", "iphone17")


def adb(*a):
    try:
        return subprocess.check_output([ADB, "-s", SERIAL] + list(a),
                                       stderr=subprocess.STDOUT).decode("utf-8", "ignore").strip()
    except Exception:
        return ""


CAPTURE_JS = r"""
rpc.exports.dumpCapture = function () {
  var out = {};
  Java.perform(function () {
    try { out.netHeaders = JSON.parse(rpc.exports.netHeaders()); } catch(e){ out.netHeadersErr=String(e); }
    try { out.headerCapture = JSON.parse(rpc.exports.headerCapture()); } catch(e){}
    try { out.buildParamsOut = JSON.parse(rpc.exports.buildParamsOut()); } catch(e){}
    // 找最近有响应的 w4j（api 含 recommend / search / wsearch）
    var arr = [];
    try {
      Java.choose('tb/w4j', {
        onMatch: function (inst) {
          try {
            var c = inst.c.value; if (!c) return;
            var api = inst.b.value ? String(inst.b.value.getApiName()) : '';
            if (api.indexOf('ecomm') < 0 && api.indexOf('search') < 0 &&
                api.indexOf('Search') < 0 && api.indexOf('wsearch') < 0) return;
            var o = {api: api};
            try { o.ret = String(c.getRet()); } catch(e){}
            try { var jo=c.getDataJsonObject(); o.data = jo ? String(jo.toString()).substring(0,500) : null; } catch(e){}
            arr.push(o);
          } catch(e){}
        }, onComplete: function () {}
      });
    } catch(e){}
    out.responses = arr;
  });
  return JSON.stringify(out);
};
"""


def ui_search():
    """后台线程：点搜索框 -> 输入关键词 -> 回车。"""
    time.sleep(3)
    print("[*] UI: 点搜索框", flush=True)
    adb("shell", "input", "tap", "200", "138")
    time.sleep(2)
    print("[*] UI: 输入", KEYWORD, flush=True)
    # adb input text 不支持中文，iphone17 是纯 ASCII OK
    adb("shell", "input", "text", KEYWORD)
    time.sleep(1)
    print("[*] UI: 回车搜索", flush=True)
    adb("shell", "input", "keyevent", "66")
    time.sleep(8)


def main():
    pid = adb("shell", "pidof", "com.taobao.taobao")
    pid = pid.split()[0] if pid else ""
    if not pid:
        print("[!] 淘宝未运行"); return
    print("[*] 设备", SERIAL, "淘宝 PID", pid, flush=True)

    with open(BUNDLE, encoding="utf-8") as f:
        source = f.read()
    sess = None
    try:
        dev = frida.get_device(SERIAL, timeout=10)
        sess = dev.attach(int(pid))
        script = sess.create_script(source + "\n" + CAPTURE_JS)
        script.on("message", lambda m, d: None)
        script.load()
        time.sleep(2)
        print("[*] hooks ready:", flush=True)
        try:
            st = json.loads(script.exports_sync.status())
            print("   ", json.dumps(st.get("hookStatus", st), ensure_ascii=False)[:800], flush=True)
        except Exception:
            pass

        t = threading.Thread(target=ui_search, daemon=True)
        t.start()
        t.join()

        out = json.loads(script.exports_sync.dump_capture())
        print("\n" + "=" * 70)
        print("UI 真实搜索请求凭证 (ground truth):")
        print(json.dumps(out, ensure_ascii=False, indent=1)[:15000])
        print("=" * 70)

        # 保存
        with open(os.path.join(os.path.dirname(__file__), "..", "docs", "captures",
                               "ui_search_groundtruth.json"), "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print("[*] 已保存 ui_search_groundtruth.json")
    except Exception as e:
        print("[!] 异常:", str(e)[:500], flush=True)
    finally:
        try:
            if sess: sess.detach()
        except Exception:
            pass


if __name__ == "__main__":
    main()
