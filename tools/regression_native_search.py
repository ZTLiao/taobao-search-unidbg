#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""回归测试：免登录状态下用真机 App 原生 Mtop 栈发文本/图片搜索，看能否出真实数据。

原理（docs/HOOK_GUIDE.md 17-18 章）：
  走 App 自己的 MtopBuilder.syncRequest()，请求 100% 经 anetwork 原生协议栈，
  自动原生签名 + 原生请求形态，绕开手工 HTTP form 被 bixi 标 wh_ttid=pc 的 web 风控。

当前环境：非 root + 重打包 gadget APK（listen 27043, on_load=resume）。
  resume 模式下 App 正常启动，gadget listener 常驻，按进程名 "Gadget" attach。

用法：python3 -u tools/regression_native_search.py [设备serial] [--text-only]
"""
import os, sys, time, json, base64, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ADB = 'C:/Users/pc/rea-tools/platform-tools/adb.exe'
BUNDLE = os.path.join(HERE, 'frida', 'rpc_native_only_bundle.js')
IMAGE = os.path.join(HERE, 'assets', 'iphone18.jpg')
GADGET_PORT = 27043
TEXT_API = 'mtop.relationrecommend.MtopRecommend.recommend'
IMAGE_API = 'mtop.relationrecommend.PailitaoRecommend.recommend'
TTID = '231200@taobao_android_10.69.10'


def sh(dev, cmd, capture=True):
    return subprocess.run([ADB, '-s', dev, 'shell', cmd], capture_output=capture)


def text_data(q='iphone'):
    return json.dumps({"requestAlias": "wsearch", "isEnterSrpSearch": "true",
                       "appId": "66", "q": q, "n": "20", "page": "1"},
                      ensure_ascii=False, separators=(',', ':'))


def image_data(path, q='iphone'):
    p = {"region": "full", "full_region_size": "full", "biz_type": "pai",
         "subSearchType": "imageText_v3", "m": "api4etao", "n": "60",
         "appId": "32969", "_sid_": "69148", "scene": "multiObject",
         "page": 1, "from": "", "pssource": "sy",
         "extraParams": "use_multi_cat:1;use_pid_summary:1;cat_deleted:1;use_pid_tag:1;extend_count:3"}
    if os.path.exists(path):
        with open(path, 'rb') as f:
            p['strimg'] = base64.b64encode(f.read()).decode('ascii')
    if q:
        p['q'] = q
    inner = json.dumps(p, ensure_ascii=False, separators=(',', ':'))
    return json.dumps({"params": inner, "appId": "32969"}, ensure_ascii=False, separators=(',', ':'))


def call_native(script, api, data, label):
    req = {"api": api, "version": "1.0", "data": data, "ttid": TTID,
           "method": "POST", "headers": {}}
    print('\n========== %s ==========' % label, flush=True)
    print('api=%s data.len=%d' % (api, len(data)), flush=True)
    try:
        r = script.exports_sync.native_search(json.dumps(req, ensure_ascii=False))
        out = json.loads(r) if isinstance(r, str) else r
        print('retCode=%s retMsg=%s' % (out.get('retCode'), out.get('retMsg')))
        print('instance=%s score=%s step=%s error=%s' % (
            out.get('instanceId'), out.get('instanceScore'), out.get('step'), out.get('error')))
        print('ret=%s' % str(out.get('ret'))[:200])
        data_s = out.get('data') or ''
        print('data.len=%d head=%s' % (len(data_s), data_s[:600]))
        real = any(k in data_s.lower() for k in ('item', 'title', 'price', 'auction', 'rawtitle'))
        risk = any(k in data_s for k in ('USER_VALIDATE', 'RGV587', 'FAIL_SYS', ' punish', 'LOGIN'))
        print('>>> 判定: real_items=%s risk=%s' % (real, risk), flush=True)
        with open(os.path.join(HERE, '..', 'regression_%s.json' % label), 'w', encoding='utf-8') as f:
            json.dump(out, f, ensure_ascii=False, indent=1)
        return out
    except Exception as e:
        print('调用异常:', str(e)[:500], flush=True)
        return None


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    text_only = '--text-only' in sys.argv
    dev = args[0] if args else subprocess.check_output(
        [ADB, 'devices']).decode().split('device\n')[0].strip().splitlines()[-1]
    print('device:', dev, flush=True)

    subprocess.run([ADB, '-s', dev, 'forward', 'tcp:%d' % GADGET_PORT,
                    'tcp:%d' % GADGET_PORT], check=True)

    import frida
    gadget = frida.get_device_manager().add_remote_device('127.0.0.1:%d' % GADGET_PORT)

    # 冷启动 + 等完全初始化（resume 模式无暂停）
    sh(dev, 'am force-stop com.taobao.taobao')
    time.sleep(3)
    sh(dev, 'logcat -c')
    print('launching app...', flush=True)
    subprocess.Popen([ADB, '-s', dev, 'shell',
                      'am start -n com.taobao.taobao/com.taobao.tao.welcome.Welcome'],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('waiting app settle (18s)...', flush=True)
    time.sleep(18)

    # 按进程名 attach（bridge 的成熟做法）
    session = None
    script = None
    for attempt in range(30):
        try:
            procs = gadget.enumerate_processes()
            print('gadget procs:', [(p.pid, p.name) for p in procs], flush=True)
            if not procs:
                time.sleep(1)
                continue
            name = procs[0].name
            session = gadget.attach(name)
            src = open(BUNDLE, encoding='utf-8').read()
            script = session.create_script(src)
            script.on('message', lambda m, d: print('[FRIDA]', m.get('payload', m.get('description', m)))
                      if m['type'] in ('log', 'error') else None)
            script.load()
            print('attached name=%s ping=%s' % (name, script.exports_sync.ping()), flush=True)
            break
        except Exception as e:
            print('attach retry %d: %s' % (attempt, str(e)[:120]), flush=True)
            try:
                if session: session.detach()
            except Exception:
                pass
            time.sleep(1)
    if script is None:
        print('ERROR: gadget attach 失败')
        return 1

    call_native(script, TEXT_API, text_data('iphone'), 'text_iphone')

    if not text_only:
        time.sleep(3)
        img_path = os.path.abspath(IMAGE)
        print('\nimage: %s exists=%s' % (img_path, os.path.exists(img_path)), flush=True)
        call_native(script, IMAGE_API, image_data(img_path, 'iphone'), 'image_iphone')

    try:
        session.detach()
    except Exception:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
