#!/usr/bin/env python3
"""验证真机主动签名能力：注入 hook 后调用 signByInner 对搜索接口产四头。"""
import argparse, json, subprocess, sys, time
import frida

ADB = "/Users/liaozetao/.local/android/sdk/platform-tools/adb"
PKG = "com.taobao.taobao"


def adb(serial, *args):
    r = subprocess.run([ADB, "-s", serial] + list(args), capture_output=True, text=True, timeout=60)
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
    args = ap.parse_args()

    dev = frida.get_device(args.serial, timeout=10)
    pids = adb(args.serial, "shell", "pidof", PKG).strip().split()
    if not pids:
        print("[!] 淘宝未运行"); sys.exit(1)
    session = dev.attach(int(pids[0]))
    with open(args.bundle, encoding="utf-8") as f:
        source = f.read()
    script = session.create_script(source)
    script.load()
    # 等待 App 触发几次 r() 以捕获 innerSign 实例
    print("[*] 等待捕获 innerSign 实例...")
    for i in range(6):
        time.sleep(3)
        st = json.loads(call(script, "status"))
        print("  t+%ds rCall=%d hasInner=%s" % ((i + 1) * 3, st.get("rCallCount", 0), st.get("hasInnerSign")))
        if st.get("rCallCount", 0) >= 2 and st.get("hasInnerSign"):
            break

    # 构造搜索接口参数（真机 10.69.10 搜索主接口）
    search_data = json.dumps({
        "requestAlias": "wsearch",
        "isEnterSrpSearch": "true",
        "appId": "66",
        "q": "iphone18",
        "n": "20",
        "page": "1",
        "from": "search",
    }, separators=(",", ":"))
    payload = {
        # signByMtop 读取顶层 api/version/data
        "data": search_data,
        "api": "mtop.relationrecommend.mtoprecommend.recommend",
        "version": "1.0",
        "params": {
            "data": search_data,
            "appKey": "21646297",
            "api": "mtop.relationrecommend.mtoprecommend.recommend",
            "v": "1.0",
            "t": str(int(time.time())),
            "utdid": "awJ3hY/Mq3EDAMWt0Bs6MAqV",
            "deviceId": "AuBCx84bur5HR28RMM72yrJz4vwoHvSvwGKrf56_wj6j",
            "ttid": "231200@taobao_android_10.69.10",
            "extdata": "openappkey=DEFAULT_AUTH",
            "x-features": "27",
            "mtopBusiness": "true",
        },
        "extend": {
            "pageId": "taobao://s.taobao.com/search",
            "pageName": "com.taobao.search.uniform.SearchActivity",
        },
        "requestId": "r_active_test",
    }

    pretty("SIGN_BY_INNER(搜索接口主动签名)", call(script, "signByInner", json.dumps(payload)))

    # 也测试 signByMtop（复用真机 Mtop 上下文）
    pretty("SIGN_BY_MTOP(搜索接口)", call(script, "signByMtop", json.dumps(payload)))

    session.detach()
    print("\n[*] DONE")


if __name__ == "__main__":
    main()
