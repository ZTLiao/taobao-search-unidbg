#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
m-sign 算法探测：协议层已用 m-* 头族突破（PROTOVER_MISSED -> REQUEST_EXPIRED）。
系统测试 m-sign / m-t 的构造方式，目标让 REQUEST_EXPIRED 消失。

已知:
  m-pv=8.1.0 + m-appkey=21646297 + m-sign + m-t=1 -> FAIL_SYS_REQUEST_EXPIRED
候选 m-sign 构造:
  1. x-sign (native 四头 sign)  -- 已试，REQUEST_EXPIRED
  2. MD5(m-t + token + appKey + data)  H5 风格
  3. MD5(token & m-t & appKey & data)
  4. m-t 用真实秒级时间戳 (而非 1)
  5. XOR / HMAC 变体
"""
import json, sys, time, hashlib, urllib.request, urllib.parse, urllib.error, ssl

BRIDGE = "http://127.0.0.1:9091/api/sign"
GW = "https://acs.m.taobao.com/gw/"
APPKEY = "21646297"
DATA = json.dumps({"requestAlias": "wsearch", "appId": "66",
                   "q": "iphone18", "n": "20", "sversion": "9999"},
                  ensure_ascii=False, separators=(',', ':'))
CTX = {"utdid": "awJ3hY/Mq3EDAMWt0Bs6MAqV",
       "deviceId": "AuBCx84bur5HR28RMM72yrJz4vwoHvSvwGKrf56_wj6j",
       "ttid": "231200@taobao_android_10.69.10", "xFeatures": "27"}

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE


def md5(s): return hashlib.md5(s.encode('utf-8')).hexdigest()


def get_sign():
    req = urllib.request.Request(
        BRIDGE, data=json.dumps({"api": "mtop.relationrecommend.mtoprecommend.recommend",
                                 "version": "1.0", "appKey": APPKEY,
                                 "data": DATA, "ctx": CTX}).encode(),
        headers={'Content-Type': 'application/json'})
    return json.loads(urllib.request.urlopen(req, timeout=20).read().decode())


def send(label, s, mt, msign, mpv='8.1.0'):
    t = s['t']
    form = {'jsv': '2.7.2', 'appKey': APPKEY, 't': t, 'sign': s['sign'],
            'api': s['api'], 'v': '1.0', 'type': 'json', 'dataType': 'json',
            'ttid': s['ttid'], 'data': DATA, 'utdid': CTX['utdid'],
            'deviceId': '', 'uid': '', 'sid': '', 'umt': s.get('umt', ''),
            'extdata': 'openappkey=DEFAULT_AUTH', 'x-features': '27',
            'x-app-conf-v': '0', 'x-app-ver': '10.69.10'}
    h = {'User-Agent': s['user-agent'], 'Content-Type': 'application/x-www-form-urlencoded',
         'x-t': t, 'x-app-ver': '10.69.10', 'x-features': '27', 'x-utdid': CTX['utdid'],
         'x-mini-wua': s.get('x-mini-wua', ''), 'x-sgext': s.get('x-sgext', ''),
         'x-gst': s.get('x-gst', ''),
         'm-pv': mpv, 'm-appkey': APPKEY, 'm-sign': msign, 'm-t': mt}
    req = urllib.request.Request(GW + s['api'] + '/1.0/',
                                 data=urllib.parse.urlencode(form).encode(),
                                 headers=h, method='POST')
    try:
        r = urllib.request.urlopen(req, timeout=25, context=ctx)
        raw = r.read().decode('utf-8', 'ignore')
    except urllib.error.HTTPError as e:
        raw = e.read().decode('utf-8', 'ignore')
    try:
        ret = json.loads(raw).get('ret', [''])[0]
    except Exception:
        ret = raw[:80]
    print(f"  [{label}] m-t={mt} msign={str(msign)[:16]}.. -> {ret[:90]}")


def main():
    s = get_sign()
    print("=" * 70)
    print("m-sign 算法探测 (目标: 让 REQUEST_EXPIRED 消失)")
    print("=" * 70)
    print(f"x-sign={s['sign'][:24]}.. t={s['t']}")

    # m-t 变体 + m-sign=x-sign
    for mt in ['1', s['t'], str(int(time.time())), '0', str(int(time.time()) - 30)]:
        send(f"msign=xsign mt={mt}", s, mt, s['sign'])

    # m-sign 候选构造 (m-t 用真实 t)
    t = s['t']
    candidates = {
        'md5(mt+appkey)': md5(t + APPKEY),
        'md5(mt+appkey+data)': md5(t + APPKEY + DATA),
        'md5(appkey+mt+data)': md5(APPKEY + t + DATA),
        'md5(xsign+mt)': md5(s['sign'] + t),
        'md5(mt+xsign)': md5(t + s['sign']),
        'md5(xsign)': md5(s['sign']),
        'md5(data+t+appkey)': md5(DATA + t + APPKEY),
        'xsign_raw': s['sign'],
        'xmini_wua': s.get('x-mini-wua', ''),
        'xsgext': s.get('x-sgext', ''),
    }
    print("\n--- m-sign 构造候选 (m-t=真实t) ---")
    for name, val in candidates.items():
        send(name, s, t, val)

    # m-pv 变体
    print("\n--- m-pv 变体 (msign=xsign, mt=t) ---")
    for mpv in ['8.1.0', '6.3', '1.0', '7.0.0', '9.0.0', '10.0.0']:
        send(f"mpv={mpv}", s, t, s['sign'], mpv=mpv)


if __name__ == '__main__':
    main()
