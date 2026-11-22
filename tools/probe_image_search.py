#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
图片搜索一体化探针：单进程内 attach 真机 -> 真机签名 -> 立即发真实网关，
避免跨进程桥接在 userdebug GSI 系统崩溃窗口下的不可靠。

用法: python3 tools/probe_image_search.py [--image /tmp/tb_img/iphone18.jpg] [--q iphone18]
"""
import argparse, base64, json, os, sys, time, subprocess
import urllib.request, urllib.parse, urllib.error, ssl

import frida

ADB = "/Users/liaozetao/.local/android/sdk/platform-tools/adb"
SERIAL = "cb76b262"
BUNDLE = os.path.join(os.path.dirname(__file__), "frida", "rpc_sign_bundle.js")
GW = "https://acs.m.taobao.com/gw/"
APPKEY = "21646297"
API = "mtop.relationrecommend.PailitaoRecommend.recommend"
CTX = {
    "utdid": "awJ3hY/Mq3EDAMWt0Bs6MAqV",
    "deviceId": "AuBCx84bur5HR28RMM72yrJz4vwoHvSvwGKrf56_wj6j",
    "ttid": "231200@taobao_android_10.69.10",
    "xFeatures": "27",
}

sslctx = ssl.create_default_context()
sslctx.check_hostname = False
sslctx.verify_mode = ssl.CERT_NONE


def adb(*args):
    try:
        return subprocess.check_output([ADB, "-s", SERIAL] + list(args),
                                       stderr=subprocess.STDOUT).decode("utf-8", "ignore").strip()
    except subprocess.CalledProcessError:
        return ""


def ensure_taobao():
    """确保淘宝主进程存活，崩溃则自动重启（userdebug GSI 不稳定）。"""
    pid = adb("shell", "pidof", "com.taobao.taobao")
    if pid:
        return pid.split()[0]
    print("[*] 淘宝未运行，自动重启...")
    adb("shell", "monkey", "-p", "com.taobao.taobao",
        "-c", "android.intent.category.LAUNCHER", "1")
    for _ in range(20):
        time.sleep(1.5)
        pid = adb("shell", "pidof", "com.taobao.taobao")
        if pid:
            print("[*] 淘宝重启完成 PID:", pid.split()[0])
            return pid.split()[0]
    return ""


def build_data(args):
    """图片搜索业务参数：strimg(base64) 走图片上传路径；q 仅作辅助文本。"""
    p = {
        "region": "full",
        "full_region_size": "full",
        "biz_type": "pai",
        "subSearchType": "imageText_v3",
        "m": "api4etao",
        "n": "60",
        "appId": "32969",
        "_sid_": "69148",
        "scene": "multiObject",
        "page": 1,
        "from": "",
        "pssource": "sy",
        "extraParams": "use_multi_cat:1;use_pid_summary:1;cat_deleted:1;use_pid_tag:1;extend_count:3",
    }
    if args.image and os.path.exists(args.image):
        with open(args.image, "rb") as f:
            p["strimg"] = base64.b64encode(f.read()).decode("ascii")
    elif args.image_url:
        p["searchimg"] = args.image_url
        p["region"] = "0,0,0,0"
    if args.q:
        p["q"] = args.q
    inner = json.dumps(p, ensure_ascii=False, separators=(",", ":"))
    # 真机 SDK (ImageSearchMtopUtil) 与文档16章记录：外层 params + appId 封装
    if getattr(args, "wrapped", False):
        return json.dumps({"params": inner, "appId": "32969"},
                          ensure_ascii=False, separators=(",", ":"))
    return inner


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default="/tmp/tb_img/iphone18.jpg")
    ap.add_argument("--image-url", default="")
    ap.add_argument("--q", default="iphone18")
    ap.add_argument("--wrapped", action="store_true",
                    help="用真机SDK外层封装 {\"params\":\"{...}\",\"appId\":\"32969\"}")
    args = ap.parse_args()

    data = build_data(args)
    print("[*] 图片搜索 data 长度:", len(data), " 含 strimg:", "strimg" in data)

    payload = {
        "api": API, "version": "1.0", "appKey": APPKEY,
        "data": data, "ctx": CTX,
    }
    with open(BUNDLE, "r", encoding="utf-8") as f:
        source = f.read()

    # userdebug GSI 系统组件会随机 SIGABRT 拖垮淘宝进程，签名带自动重启重试
    s = None
    for attempt in range(1, 4):
        pid = ensure_taobao()
        if not pid:
            print("[!] 淘宝无法启动")
            return
        print("[*] 淘宝 PID:", pid, "(尝试 %d/3)" % attempt)
        session = None
        try:
            dev = frida.get_device(SERIAL, timeout=10)
            session = dev.attach(int(pid))
            script = session.create_script(source)
            script.on("message", lambda m, d: None)
            script.load()
            time.sleep(2)
            print("[*] 调用真机 signByMtop 签名...")
            raw = script.exports_sync.sign_by_mtop(json.dumps(payload, ensure_ascii=False))
            s = json.loads(raw) if isinstance(raw, str) else raw
            if s.get("error") or not s.get("sign"):
                print("[!] 签名失败:", s.get("error"))
                s = None
        except Exception as e:
            print("[!] attach/签名异常:", str(e)[:120])
            s = None
        finally:
            try:
                if session: session.detach()
            except Exception:
                pass
        if s:
            break
        print("[*] 等待重试...")
        time.sleep(3)

    if not s:
        print("[!] 3 次尝试均未能签名，放弃")
        return
    print("[*] 真机签名成功: sign=%s.. x-gst=%s pv=%s" % (
        str(s.get("sign"))[:20], bool(s.get("x-gst")), s.get("pv")))
    # 诊断：签名时真机实际用的 data 是否与我们传入的一致
    sdata = s.get("data", "")
    import hashlib
    if os.environ.get("DUMP_SIGN"):
        print("[*] 真机签名返回全部字段:")
        for k in sorted(s.keys()):
            v = str(s[k])
            print("    %-24s = %s" % (k, v[:120]))
    print("[*] 签名诊断: changed=%s" % s.get("_changed"))
    print("[*] 签名诊断: 传入data长度=%d 返回data长度=%d 相等=%s" % (
        len(data), len(str(sdata)), str(sdata) == data))
    print("[*] 签名诊断: 传入md5=%s 返回md5=%s" % (
        hashlib.md5(data.encode()).hexdigest(),
        hashlib.md5(str(sdata).encode()).hexdigest()))

    # 构造完整请求（MtopHttpClient app 模式同款，含 m-* 头族）
    t = s.get("t", str(int(time.time())))
    mt = str(int(time.time()))  # 关键：当前秒级时间戳
    form = {
        "jsv": "2.7.2", "appKey": APPKEY, "t": t, "sign": s["sign"],
        "api": s.get("api", API), "v": "1.0", "type": "json", "dataType": "json",
        "ttid": s.get("ttid", CTX["ttid"]), "data": data,
        "utdid": s.get("utdid") or CTX["utdid"],
        "deviceId": s.get("deviceId") or s.get("x-devid") or "",
        "uid": s.get("uid") or "", "sid": s.get("sid") or "",
        "umt": s.get("umt", ""), "extdata": s.get("extdata", "openappkey=DEFAULT_AUTH"),
        "x-features": s.get("x-features", "27"),
        "x-app-conf-v": s.get("x-app-conf-v", "0"),
        "x-app-ver": s.get("x-app-ver", "10.69.10"),
        "netType": s.get("netType", "WIFI"), "nq": s.get("nq", "WIFI"),
        "f-refer": s.get("f-refer", "mtop"),
        "x-page-url": s.get("x-page-url", ""), "x-page-name": s.get("x-page-name", ""),
    }
    headers = {
        "User-Agent": s.get("user-agent", "MTOPSDK/3.1.1.7 (Android;13;unknown;TrebleDroid vanilla) DeviceType(Phone)"),
        "Content-Type": "application/x-www-form-urlencoded",
        "x-t": t, "x-app-ver": "10.69.10", "x-features": "27",
        "x-app-conf-v": s.get("x-app-conf-v", "0"),
        "x-c-traceid": s.get("x-c-traceid", ""), "x-falco-id": s.get("x-falco-id", ""),
        "x-page-url": s.get("x-page-url", ""), "x-page-name": s.get("x-page-name", ""),
        "f-refer": "mtop", "x-utdid": CTX["utdid"], "x-devid": CTX["deviceId"],
        "x-mini-wua": s.get("x-mini-wua", ""), "x-sgext": s.get("x-sgext", ""),
        "x-gst": s.get("x-gst", ""),
        # m-* 协议头族（已攻破的门槛）
        "m-pv": "8.1.0", "m-appkey": APPKEY, "m-sign": s["sign"], "m-t": mt,
    }
    # session 已在签名循环中 detach（减少崩溃影响）

    url = GW + API + "/1.0/"
    body = urllib.parse.urlencode(form).encode("utf-8")
    print("[*] 发送真实网关请求 (%d bytes body)..." % len(body))
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        r = urllib.request.urlopen(req, timeout=40, context=sslctx)
        raw_resp = r.read().decode("utf-8", "ignore")
        resp_headers = dict(r.headers)
    except urllib.error.HTTPError as e:
        raw_resp = e.read().decode("utf-8", "ignore")
        resp_headers = dict(e.headers)
    except Exception as e:
        print("[!] 网关请求异常:", e)
        return

    print("\n" + "=" * 70)
    print("图片搜索完整响应")
    print("=" * 70)
    try:
        j = json.loads(raw_resp)
        print(json.dumps(j, ensure_ascii=False, indent=1)[:8000])
    except Exception:
        print(raw_resp[:8000])
    print("\n--- 关键响应头 ---")
    for k in ("bx-action", "bxpunish", "bx-retry", "Location", "Set-Cookie"):
        for kk in resp_headers:
            if kk.lower() == k.lower():
                print(" %s: %s" % (kk, str(resp_headers[kk])[:200]))


if __name__ == "__main__":
    main()
