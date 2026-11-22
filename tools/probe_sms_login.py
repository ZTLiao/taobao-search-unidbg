#!/usr/bin/env python3
"""探针：淘宝短信登录接口 smssend/smslogin 是否可达、参数结构、风控状态。

用现有 Java 服务的 unidbg 签名后端对 acs 网关发请求。
不需要真账号，先用假手机号探测网关响应类型（参数错误 vs 风控拦截）。

前置：先启动 app 模式 + unidbg 后端的服务（见下方用法）。
用法：python3 tools/probe_sms_login.py --port 9101 --phone 13800138000
"""
import argparse, json, time, hashlib, urllib.request, urllib.parse

GW = "https://acs.m.taobao.com/gw/"
APPKEY = "21646297"
TTID = "231200@taobao_android_10.69.10"
VERSION = "1.0"


def sign_unidbg(api, data, t):
    """调 Java 服务的签名端点（若有），否则本地占位。
    这里直接用 gateway 发一个带空 sign 的请求，观察网关在最外层是否接受。"""
    return ""


def raw_call(api, data, sign, t, utdid):
    params = {
        "jsv": "2.7.2", "appKey": APPKEY, "t": str(t), "sign": sign,
        "api": api, "v": VERSION, "type": "json", "dataType": "json",
        "ttid": TTID, "data": data,
        "utdid": utdid, "umt": "", "extdata": "openappkey=DEFAULT_AUTH",
        "x-features": "27", "netType": "HSPA", "nq": "3G", "f-refer": "mtop",
    }
    body = urllib.parse.urlencode(params).encode()
    url = GW + api + "/" + VERSION + "/"
    headers = {
        "User-Agent": "MTOPSDK/3.1.1.7 (Android;15;Google;FP4) DeviceType(Phone)",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "x-app-ver": "10.69.10", "x-features": "27", "x-app-conf-v": "0",
        "netType": "HSPA", "nq": "3G", "f-refer": "mtop", "umt": "",
        "m-pv": "8.1.0", "m-appkey": APPKEY, "m-sign": sign or str(t),
        "m-t": str(t), "x-utdid": utdid,
    }
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        resp = urllib.request.urlopen(req, timeout=20)
        return resp.status, resp.read().decode("utf-8", "ignore"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore"), dict(e.headers)
    except Exception as e:
        return -1, str(e), {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phone", default="13800138000")
    ap.add_argument("--api", default="mtop.alibaba.havana.login.smssend")
    args = ap.parse_args()
    utdid = "".join(__import__("random").choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(24))
    t = int(time.time())
    # smssend 参数：loginId(手机号) countryCode scene source
    data = json.dumps({
        "loginId": args.phone, "countryCode": "86",
        "scene": "login", "source": "taobao", "codeLength": "6",
    }, ensure_ascii=False, separators=(",", ":"))
    print("[*] api=%s phone=%s" % (args.api, args.phone))
    print("[*] data=%s" % data)
    code, body, hdrs = raw_call(args.api, data, "", t, utdid)
    print("[*] HTTP=%d" % code)
    print("[*] body=%s" % body[:1500])
    print("[*] set-cookie=%s" % hdrs.get("Set-Cookie", "")[:500])


if __name__ == "__main__":
    main()
