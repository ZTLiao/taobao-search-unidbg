#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网关形态对照实验：用真机桥接签名，系统测试不同请求形态，
定位 FAIL_SYS_PROTOVER_MISSED::缺少协议版本m-pv 的触发/消除条件。

变量矩阵：
  - api 大小写: MtopRecommend(工程) / mtoprecommend(真机日志)
  - pv 参数: 无 / 6.3 (form body)
  - x-pv 头: 无 / 6.3
  - 四头位置: header / form
  - x-gst 头: 无 / 有
  - method: POST / GET
  - 登录 cookie: 无 (当前只有游客态)

用法: python3 tools/gateway_matrix.py
"""
import json, sys, time, urllib.request, urllib.parse, urllib.error, ssl

BRIDGE = "http://127.0.0.1:9091/api/sign"
GW = "https://acs.m.taobao.com/gw/"
PYBIN = sys.executable

DATA = json.dumps({"requestAlias": "wsearch", "appId": "66",
                   "q": "iphone18", "n": "20",
                   "sversion": "9999"}, ensure_ascii=False, separators=(',', ':'))

CTX = {
    "utdid": "awJ3hY/Mq3EDAMWt0Bs6MAqV",
    "deviceId": "AuBCx84bur5HR28RMM72yrJz4vwoHvSvwGKrf56_wj6j",
    "ttid": "231200@taobao_android_10.69.10",
    "xFeatures": "27",
}

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def sign(api):
    payload = {"api": api, "version": "1.0", "appKey": "21646297",
               "data": DATA, "ctx": CTX}
    req = urllib.request.Request(
        BRIDGE, data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode('utf-8', 'ignore'))


def probe(label, s, *, api_case='lower', pv=None, xpv=None,
          four_in_form=False, xgst=False, method='POST', h5=False,
          mpv=None, mappkey=None, msign=None, mt=None):
    api = s['api']
    appkey = s['appKey']
    v = s.get('v', '1.0')
    t = s.get('t', str(int(time.time())))
    signval = s.get('sign', '')

    # form 参数（真机 buildParams 全集）
    form = {
        'jsv': '2.7.2', 'appKey': appkey, 't': t, 'sign': signval,
        'api': api, 'v': v, 'type': 'json', 'dataType': 'json',
        'ttid': s.get('ttid', CTX['ttid']), 'data': DATA,
        'utdid': s.get('utdid', CTX['utdid']),
        'deviceId': s.get('deviceId', ''), 'uid': s.get('uid', ''),
        'sid': s.get('sid', ''), 'umt': s.get('umt', ''),
        'extdata': s.get('extdata', 'openappkey=DEFAULT_AUTH'),
        'x-features': s.get('x-features', '27'),
        'x-app-conf-v': s.get('x-app-conf-v', '0'),
        'x-app-ver': s.get('x-app-ver', '10.69.10'),
        'netType': s.get('netType', 'WIFI'), 'nq': s.get('nq', 'WIFI'),
        'f-refer': s.get('f-refer', 'mtop'),
        'x-page-url': s.get('x-page-url', ''),
        'x-page-name': s.get('x-page-name', ''),
    }
    if pv is not None:
        form['pv'] = pv

    # header 集
    headers = {
        'User-Agent': s.get('user-agent', 'MTOPSDK/3.1.1.7 (Android;13;unknown;TrebleDroid vanilla) DeviceType(Phone)'),
        'Content-Type': 'application/x-www-form-urlencoded',
        'x-t': t, 'x-app-ver': s.get('x-app-ver', '10.69.10'),
        'x-features': '27', 'x-app-conf-v': s.get('x-app-conf-v', '0'),
        'x-c-traceid': s.get('x-c-traceid', ''), 'x-falco-id': s.get('x-falco-id', ''),
        'x-page-url': s.get('x-page-url', ''), 'x-page-name': s.get('x-page-name', ''),
        'f-refer': 'mtop',
        'x-utdid': CTX['utdid'], 'x-devid': CTX['deviceId'],
    }
    # 四头
    four = {k: s.get(k, '') for k in ('sign', 'x-mini-wua', 'x-sgext', 'x-gst', 'x-umt')}
    if four_in_form:
        for k, val in four.items():
            if val: form[k] = val
    else:
        for k in ('x-mini-wua', 'x-sgext', 'x-gst', 'x-umt'):
            if s.get(k): headers[k] = s[k]
    if xgst and s.get('x-gst'):
        headers['x-gst'] = s['x-gst']
    if xpv is not None:
        headers['x-pv'] = xpv
    # m-* 头族（网关索要的协议版本头）
    if mpv is not None: headers['m-pv'] = mpv
    if mappkey is not None: headers['m-appkey'] = mappkey
    if msign is not None: headers['m-sign'] = msign
    if mt is not None: headers['m-t'] = mt

    body = urllib.parse.urlencode(form).encode('utf-8')
    url = GW + api + '/' + v + '/'
    if method == 'GET':
        url += '?' + body.decode('utf-8')
        req = urllib.request.Request(url, headers=headers, method='GET')
    else:
        req = urllib.request.Request(url, data=body, headers=headers, method='POST')

    try:
        with urllib.request.urlopen(req, timeout=25, context=ctx) as r:
            raw = r.read().decode('utf-8', 'ignore')
            bx = r.headers.get('bx-action') or r.headers.get('bxpunish') or ''
    except urllib.error.HTTPError as e:
        raw = e.read().decode('utf-8', 'ignore')
        bx = e.headers.get('bx-action') or e.headers.get('bxpunish') or ''
    except Exception as e:
        print(f"  [{label}] EXCEPTION {e}")
        return
    ret = raw[:110].replace('\n', ' ')
    print(f"  [{label}] m-pv={mpv} m-sign={'Y' if msign else 'N'} method={method} pv={pv} xpv={xpv} bx={bx}")
    print(f"      ret={ret}")


def main():
    print("=" * 72)
    print("网关形态对照实验 (真机签名 + 真实网关)")
    print("=" * 72)
    lower = sign('mtop.relationrecommend.mtoprecommend.recommend')
    if lower.get('error'):
        print("签名失败:", lower.get('error'))
        return

    print("\n--- A组: api 大小写 ---")
    probe("A1 小写api 基线", lower)
    upper = sign('mtop.relationrecommend.MtopRecommend.recommend')
    probe("A2 大写api 基线", upper)

    print("\n--- B组: pv 参数(form) ---")
    probe("B1 小写+pv6.3(form)", lower, pv='6.3')
    probe("B2 大写+pv6.3(form)", upper, pv='6.3')

    print("\n--- C组: x-pv 头 ---")
    probe("C1 小写+xpv6.3", lower, xpv='6.3')
    probe("C2 小写+pv6.3+xpv6.3", lower, pv='6.3', xpv='6.3')

    print("\n--- D组: 四头放 form ---")
    probe("D1 小写+4inForm", lower, four_in_form=True)
    probe("D2 小写+pv+4inForm", lower, pv='6.3', four_in_form=True)

    print("\n--- E组: GET ---")
    probe("E1 小写+pv+GET", lower, pv='6.3', method='GET')

    print("\n--- F组: x-gst ---")
    probe("F1 小写+pv+xgst", lower, pv='6.3', xgst=True)

    print("\n--- G组: m-pv 头族 (关键验证) ---")
    probe("G1 m-pv=6.3", lower, mpv='6.3')
    probe("G2 m-pv=8.1.0", lower, mpv='8.1.0')
    probe("G3 m-pv=8.1.0+m-appkey", lower, mpv='8.1.0', mappkey='21646297')
    probe("G4 m-pv=8.1.0+全套(sign作msign)", lower, mpv='8.1.0', mappkey='21646297',
          msign=lower.get('sign', ''), mt='1')

    print("\n完成")


if __name__ == '__main__':
    main()
