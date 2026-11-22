#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
决定性实验：图搜请求的签名 + 设备态 + 网络出口 IP 三者全部来自真机。

流程：
  1) Frida attach 淘宝主进程 -> signByMtop(wrapped data) 拿真机签名与完整参数
  2) 在真机进程内用真机自身网络栈直接发 mtop 请求（MtopBusiness / HttpURLConnection via Java.perform）
     —— 不用 Mac 的 IP，彻底消除"签名真机、出口电脑"的不一致
  3) 打印响应

用法: python3 tools/probe_image_ondevice.py --image /tmp/tb_img/iphone18.jpg
"""
import argparse, base64, json, os, sys, time
import urllib.parse

import frida

ADB = "/Users/liaozetao/.local/android/sdk/platform-tools/adb"
SERIAL = "cb76b262"
BUNDLE = os.path.join(os.path.dirname(__file__), "frida", "rpc_sign_bundle.js")
API = "mtop.relationrecommend.PailitaoRecommend.recommend"
APPKEY = "21646297"
CTX = {"utdid": "awJ3hY/Mq3EDAMWt0Bs6MAqV", "ttid": "231200@taobao_android_10.69.10"}


def adb(*args):
    try:
        return __import__("subprocess").check_output(
            [ADB, "-s", SERIAL] + list(args), stderr=__import__("subprocess").STDOUT
        ).decode("utf-8", "ignore").strip()
    except Exception:
        return ""


TEXT_API = "mtop.relationrecommend.MtopRecommend.recommend"


def build_data(args):
    if getattr(args, "text", False):
        # 真机统一搜索页 data（session 9 抓包形态）
        p = {
            "requestAlias": "wsearch", "isEnterSrpSearch": "true",
            "appId": "66", "q": args.q or "iphone18", "n": "20",
            "page": "1", "from": "",
        }
        return json.dumps(p, ensure_ascii=False, separators=(",", ":"))
    p = {
        "region": "full", "full_region_size": "full", "biz_type": "pai",
        "subSearchType": "imageText_v3", "m": "api4etao", "n": "60",
        "appId": "32969", "_sid_": "69148", "scene": "multiObject",
        "page": 1, "from": "", "pssource": "sy",
        "extraParams": "use_multi_cat:1;use_pid_summary:1;cat_deleted:1;use_pid_tag:1;extend_count:3",
    }
    if args.image and os.path.exists(args.image):
        with open(args.image, "rb") as f:
            p["strimg"] = base64.b64encode(f.read()).decode("ascii")
    if args.q:
        p["q"] = args.q
    inner = json.dumps(p, ensure_ascii=False, separators=(",", ":"))
    return json.dumps({"params": inner, "appId": "32969"}, ensure_ascii=False, separators=(",", ":"))


# Java 侧：用真机 HttpURLConnection 从真机网络栈发请求
SEND_JS = r"""
rpc.exports.sendOnDevice = function(reqJson) {
  var out = {error: null, step: 'start'};
  Java.perform(function () {
    try {
      var req = JSON.parse(reqJson);
      var URL = Java.use('java.net.URL');
      var url = URL.$new(req.url);
      out.step = 'openConnection';
      var conn = Java.cast(url.openConnection(), Java.use('java.net.HttpURLConnection'));
      conn.setRequestMethod('POST');
      conn.setDoOutput(true);
      conn.setConnectTimeout(30000);
      conn.setReadTimeout(30000);
      out.step = 'headers';
      var headers = req.headers || {};
      Object.keys(headers).forEach(function(k){ conn.setRequestProperty(k, headers[k]); });
      out.step = 'write';
      var os = conn.getOutputStream();
      var bodyBytes = Java.use('java.lang.String').$new(req.body).getBytes('UTF-8');
      os.write(bodyBytes); os.flush(); os.close();
      out.step = 'responseCode';
      var code = conn.getResponseCode();
      out.code = code;
      out.step = 'readBody';
      var is = (code < 400) ? conn.getInputStream() : conn.getErrorStream();
      var sb = Java.use('java.lang.StringBuilder').$new();
      if (is) {
        var br = Java.use('java.io.BufferedReader').$new(Java.use('java.io.InputStreamReader').$new(is, 'UTF-8'));
        var line;
        while ((line = br.readLine()) !== null) { sb.append(line); }
        br.close();
      }
      out.body = sb.toString();
      out.step = 'headers2';
      try {
        var hm = conn.getHeaderFields();
        var hs = {};
        var it = hm.keySet().iterator();
        while (it.hasNext()) {
          var k = it.next();
          if (k) hs[String(k)] = String(hm.get(k));
        }
        out.headers = hs;
      } catch (e2) { out.headers = {warn: String(e2)}; }
      conn.disconnect();
      out.step = 'done';
    } catch (e) { out.error = String(e); }
  });
  return JSON.stringify(out);
};
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default="/tmp/tb_img/iphone18.jpg")
    ap.add_argument("--image-url", default="")
    ap.add_argument("--q", default="iphone18")
    ap.add_argument("--text", action="store_true", help="对照：测文本搜索接口")
    args = ap.parse_args()

    api = TEXT_API if args.text else API
    data = build_data(args)
    print("[*] api=%s data 长度:" % api, len(data))
    payload = {"api": api, "version": "1.0", "appKey": APPKEY, "data": data,
               "ctx": CTX}

    pid = adb("shell", "pidof", "com.taobao.taobao").split()[0] if adb("shell", "pidof", "com.taobao.taobao") else ""
    if not pid:
        adb("shell", "monkey", "-p", "com.taobao.taobao", "-c",
            "android.intent.category.LAUNCHER", "1")
        for _ in range(20):
            time.sleep(1.5)
            p = adb("shell", "pidof", "com.taobao.taobao")
            if p:
                pid = p.split()[0]; break
    print("[*] 淘宝 PID:", pid)
    if not pid:
        return

    with open(BUNDLE, encoding="utf-8") as f:
        source = f.read()
    session = None
    try:
        dev = frida.get_device(SERIAL, timeout=10)
        session = dev.attach(int(pid))
        script = session.create_script(source + "\n" + SEND_JS)
        script.on("message", lambda m, d: None)
        script.load()
        time.sleep(2)
        raw = script.exports_sync.sign_by_mtop(json.dumps(payload, ensure_ascii=False))
        s = json.loads(raw) if isinstance(raw, str) else raw
        if s.get("error") or not s.get("sign"):
            print("[!] 签名失败:", s.get("error")); return
        print("[*] 真机签名 OK sign=%s.. uid=%r sid=%r" % (
            str(s["sign"])[:16], s.get("uid"), s.get("sid")))

        import hashlib
        t = s.get("t", str(int(time.time())))
        mt = str(int(time.time()))
        form = {
            "jsv": "2.7.2", "appKey": APPKEY, "t": t, "sign": s["sign"],
            "api": api, "v": "1.0", "type": "json", "dataType": "json",
            "ttid": s.get("ttid", CTX["ttid"]), "data": data,
            "utdid": s.get("utdid") or CTX["utdid"],
            "deviceId": s.get("deviceId") or "",
            "uid": s.get("uid") or "", "sid": s.get("sid") or "",
            "umt": s.get("umt", ""),
            "extdata": s.get("extdata", "openappkey=DEFAULT_AUTH"),
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
            "f-refer": "mtop", "x-utdid": s.get("utdid") or CTX["utdid"],
            "x-devid": s.get("deviceId") or "",
            "x-mini-wua": s.get("x-mini-wua", ""), "x-sgext": s.get("x-sgext", ""),
            "x-gst": s.get("x-gst", ""),
            "m-pv": "8.1.0", "m-appkey": APPKEY, "m-sign": s["sign"], "m-t": mt,
        }
        url = "https://acs.m.taobao.com/gw/" + api + "/1.0/"
        body = urllib.parse.urlencode(form)
        reqj = json.dumps({"url": url, "body": body, "headers": headers}, ensure_ascii=False)
        print("[*] 真机网络栈发送请求 body=%d bytes ..." % len(body))
        out_raw = script.exports_sync.send_on_device(reqj)
        out = json.loads(out_raw) if isinstance(out_raw, str) else out_raw
        print("\n" + "=" * 70)
        print("真机出口响应 HTTP", out.get("code"), "error=", out.get("error"))
        print("=" * 70)
        b = out.get("body", "")
        try:
            print(json.dumps(json.loads(b), ensure_ascii=False, indent=1)[:6000])
        except Exception:
            print(b[:6000])
        hs = out.get("headers", {})
        print("\n--- 关键响应头 ---")
        for k in hs:
            if k.lower() in ("bx-action", "bxpunish", "bx-retry", "location", "set-cookie"):
                print(" %s: %s" % (k, str(hs[k])[:180]))
    except Exception as e:
        print("[!] 异常:", str(e)[:200])
    finally:
        try:
            if session: session.detach()
        except Exception:
            pass


if __name__ == "__main__":
    main()
