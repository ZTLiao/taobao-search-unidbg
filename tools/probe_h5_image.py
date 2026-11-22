#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
免登录图片搜索路径探测：H5 网关游客态（_m_h5_tk 标准握手，无需真机签名）。

测试矩阵：
  - 网关: h5api.m.taobao.com/h5/  (H5 标准)
  - appKey: 12574478(H5) / 21646297(app)
  - API: PailitaoRecommend / 其他图搜候选
  - data 封装: 平铺 / {"params":"{...}","appId":"32969"} 外层
  - 图片: strimg(base64) / searchimg(URL)

握手流程（标准）：
  1) 无 token 请求 -> 网关 FAIL_SYS_TOKEN_EXPIRED + Set-Cookie: _m_h5_tk=<token>_<ts>
  2) 取 token 重算 sign=MD5(token&t&appKey&data) -> 带 Cookie 重试

用法: python3 tools/probe_h5_image.py [--image /tmp/tb_img/iphone18.jpg]
"""
import argparse, base64, json, os, sys, time, hashlib
import http.cookiejar
import urllib.request, urllib.parse, urllib.error, ssl

sslctx = ssl.create_default_context()
sslctx.check_hostname = False
sslctx.verify_mode = ssl.CERT_NONE

GW = "https://h5api.m.taobao.com/h5/"
UA_H5 = ("Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) "
         "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 "
         "Mobile/15E148 Safari/604.1")


def md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def build_biz(args):
    """真机 SDK 拍立淘业务参数（ImageSearchMtopUtil.h 逆向）"""
    p = {
        "region": "full", "full_region_size": "full",
        "biz_type": "pai", "subSearchType": "imageText_v3",
        "m": "api4etao", "n": "60", "appId": "32969",
        "_sid_": "69148", "scene": "multiObject", "page": 1,
        "from": "", "pssource": "sy",
        "extraParams": "use_multi_cat:1;use_pid_summary:1;cat_deleted:1;use_pid_tag:1;extend_count:3",
    }
    if args.image and os.path.exists(args.image):
        with open(args.image, "rb") as f:
            p["strimg"] = base64.b64encode(f.read()).decode("ascii")
    if args.image_url:
        p["searchimg"] = args.image_url
        p["region"] = "0,0,0,0"
    if args.q:
        p["q"] = args.q
    return p


class Jar:
    def __init__(self):
        self.kv = {}

    def absorb(self, headers):
        changed = False
        for k, vals in headers.items():
            if k.lower() != "set-cookie":
                continue
            for sc in (vals if isinstance(vals, list) else [vals]):
                first = sc.split(";", 2)[0].strip()
                if "=" not in first:
                    continue
                kk, vv = first.split("=", 1)
                if vv and self.kv.get(kk) != vv:
                    changed = True
                self.kv[kk] = vv
        return changed

    def header(self):
        return "; ".join("%s=%s" % (k, v) for k, v in self.kv.items())

    def token(self):
        raw = self.kv.get("_m_h5_tk", "")
        return raw.rsplit("_", 1)[0] if raw else ""


def request(api, version, appkey, data, jar, extra_form=None):
    t = str(int(time.time() * 1000))
    sign = md5("%s&%s&%s&%s" % (jar.token(), t, appkey, data))
    form = {
        "jsv": "2.7.2", "appKey": appkey, "t": t, "sign": sign,
        "api": api, "v": version, "type": "json", "dataType": "json",
        "data": data,
    }
    if extra_form:
        form.update(extra_form)
    body = urllib.parse.urlencode(form).encode("utf-8")
    headers = {
        "User-Agent": UA_H5,
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": "https://h5.m.taobao.com/",
        "Origin": "https://h5.m.taobao.com",
        "Accept": "application/json",
    }
    if jar.header():
        headers["Cookie"] = jar.header()
    req = urllib.request.Request(GW + api + "/" + version + "/",
                                 data=body, headers=headers, method="POST")
    try:
        r = urllib.request.urlopen(req, timeout=30, context=sslctx)
        raw = r.read().decode("utf-8", "ignore")
        jar.absorb(dict(r.headers))
        return raw, dict(r.headers)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "ignore")
        jar.absorb(dict(e.headers))
        return raw, dict(e.headers)
    except Exception as e:
        return json.dumps({"__exception": str(e)}), {}


def try_once(label, api, version, appkey, data):
    """两次：首次握手 + 带 token 重试"""
    jar = Jar()
    raw, hdr = request(api, version, appkey, data, jar)
    r1 = parse_ret(raw)
    changed = jar.absorb(hdr)
    r2 = raw
    if changed or "TOKEN" in r1.upper():
        raw2, hdr2 = request(api, version, appkey, data, jar)
        r2 = parse_ret(raw2)
    print("  [%s] 1st=%s -> 2nd=%s | token=%s | raw=%s" % (
        label, r1, r2, jar.token()[:12] or "-", raw[:180].replace("\n", " ")))
    return r2, raw


def parse_ret(raw):
    try:
        j = json.loads(raw)
        return str(j.get("ret", [j.get("error", "?")])[:1]) if isinstance(j.get("ret"), list) else str(j.get("ret", "?"))
    except Exception:
        return raw[:60]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default="/tmp/tb_img/iphone18.jpg")
    ap.add_argument("--image-url", default="")
    ap.add_argument("--q", default="iphone18")
    args = ap.parse_args()

    biz = build_biz(args)
    inner = json.dumps(biz, ensure_ascii=False, separators=(",", ":"))
    data_variants = {
        "flat": inner,
        "wrapped": json.dumps({"params": inner, "appId": "32969"},
                              ensure_ascii=False, separators=(",", ":")),
    }
    apis = [
        ("img", "mtop.relationrecommend.PailitaoRecommend.recommend"),
        ("text", "mtop.relationrecommend.MtopRecommend.recommend"),
        ("appsearch", "mtop.taobao.wsearch.appsearch"),
    ]
    appkeys = ["12574478", "21646297"]

    print("=" * 78)
    print("免登录图片搜索探测（H5 游客态握手）")
    print("=" * 78)
    # 先用文本接口做握手健康度自检
    print("\n[0] 握手自检: appsearch / appKey=12574478")
    try_once("appsearch", apis[2][1], "1.0", "12574478", "{}")

    for ak in appkeys:
        for dname, data in data_variants.items():
            for lname, api in apis[:2]:
                label = "%s/%s/%s" % (ak, dname, lname)
                try_once(label, api, "1.0", ak, data)
                time.sleep(0.4)


if __name__ == "__main__":
    main()
