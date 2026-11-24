#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""三路官方证书固定 + 免登录原生搜索回归测试。

在 resume 模式 gadget（listen 27043, on_load=resume）上：
  1) 冷启动淘宝，attach 到 Gadget 进程
  2) 先加载 sg_sig_full_bundle.js —— 三路固定 hook 常驻：
       路1 getPackageInfo → signatures/signingInfo 官方证书
       路2 Signature.toByteArray() → 官方证书 DER
       路3 native open/openat → SG 读的 base.apk 重定向到官方 APK
  3) 再加载 rpc_native_only_bundle.js —— nativeSearch RPC
  4) 文本 iphone + 图片 iphone18.jpg
  5) 抓 hook 命中计数 + logcat 1927/EC40002，判断三路固定是否破解 1927

用法：python3 -u tools/regression_sgfull.py [设备serial]
"""
import os, sys, time, json, base64, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ADB = 'C:/Users/pc/rea-tools/platform-tools/adb.exe'
HOOK_BUNDLE = os.path.join(HERE, 'frida', 'sg_sig_full_bundle.js')
RPC_BUNDLE = os.path.join(HERE, 'frida', 'rpc_native_only_bundle.js')
IMAGE = os.path.join(HERE, 'assets', 'iphone18.jpg')
GADGET_PORT = 27043
HOOK_STATUS = '/data/local/tmp/sg_sigfull_status.txt'
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


def dump_hook_status(dev, tag):
    st = sh(dev, 'cat ' + HOOK_STATUS + ' 2>/dev/null').stdout.decode('utf-8', 'ignore')
    print('\n=== hook status (%s) ===' % tag, flush=True)
    for line in st.splitlines():
        if ('[SG-FULL]' in line and ('hit' in line or 'redirect' in line or
            'INSTALLED' in line or 'hook ' in line or 'err' in line)):
            print('  ' + line, flush=True)
    return st


def dump_logcat_counts(dev, tag):
    logs = subprocess.run([ADB, '-s', dev, 'logcat', '-d'],
                          capture_output=True).stdout.decode('utf-8', 'ignore')
    print('\n=== logcat counts (%s) ===' % tag, flush=True)
    print('  1927       :', logs.count('errorCode 1927'), flush=True)
    print('  EC40002    :', logs.count('EC40002'), flush=True)
    print('  SIGN_ERROR :', logs.count('ANDROID_SYS_GENERATE_MTOP_SIGN_ERROR'), flush=True)
    print('  USER_VALID :', logs.count('USER_VALIDATE'), flush=True)
    # 打印含 1927 的关键行样本
    hits = [l for l in logs.splitlines() if 'errorCode 1927' in l or 'SecException 1927' in l]
    for l in hits[:6]:
        print('  | ' + l[-220:], flush=True)
    return logs


def call_native(script, api, data, label, out_dir):
    req = {"api": api, "version": "1.0", "data": data, "ttid": TTID,
           "method": "POST", "headers": {}}
    print('\n========== %s ==========' % label, flush=True)
    try:
        r = script.exports_sync.native_search(json.dumps(req, ensure_ascii=False))
        out = json.loads(r) if isinstance(r, str) else r
        print('retCode=%s retMsg=%s' % (out.get('retCode'), out.get('retMsg')))
        print('instance=%s score=%s step=%s error=%s' % (
            out.get('instanceId'), out.get('instanceScore'), out.get('step'), out.get('error')))
        data_s = out.get('data') or ''
        print('data.len=%d head=%s' % (len(data_s), data_s[:500]))
        real = any(k in data_s.lower() for k in ('item', 'title', 'price', 'auction', 'rawtitle'))
        risk = any(k in data_s for k in ('USER_VALIDATE', 'RGV587', 'FAIL_SYS', ' punish', 'LOGIN'))
        print('>>> 判定: real_items=%s risk=%s' % (real, risk), flush=True)
        with open(os.path.join(out_dir, 'regression_sgfull_%s.json' % label), 'w', encoding='utf-8') as f:
            json.dump(out, f, ensure_ascii=False, indent=1)
        return out
    except Exception as e:
        print('调用异常:', str(e)[:500], flush=True)
        return None


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    dev = args[0] if args else subprocess.check_output(
        [ADB, 'devices']).decode().split('device\n')[0].strip().splitlines()[-1]
    out_dir = os.path.join(HERE, '..')
    print('device:', dev, flush=True)

    # 0) 清 hook 状态文件 + 冷启动
    sh(dev, 'rm -f ' + HOOK_STATUS)
    sh(dev, 'am force-stop com.taobao.taobao')
    time.sleep(2)
    sh(dev, 'logcat -c')

    # 1) 端口转发 + 连接 gadget
    subprocess.run([ADB, '-s', dev, 'forward', 'tcp:%d' % GADGET_PORT,
                    'tcp:%d' % GADGET_PORT], check=True)
    import frida
    gadget = frida.get_device_manager().add_remote_device('127.0.0.1:%d' % GADGET_PORT)

    # 2) 启动 App
    subprocess.Popen([ADB, '-s', dev, 'shell',
                      'am start -n com.taobao.taobao/com.taobao.tao.welcome.Welcome'],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('launching app, waiting settle (18s)...', flush=True)
    time.sleep(18)

    # 3) attach Gadget
    session = None
    hook_script = None
    for attempt in range(30):
        try:
            procs = gadget.enumerate_processes()
            if not procs:
                time.sleep(1); continue
            name = procs[0].name
            session = gadget.attach(name)

            def on_msg(msg, data):
                if msg['type'] in ('log', 'error'):
                    print('[FRIDA]', msg.get('payload', msg.get('description', msg)), flush=True)

            # 3a) 先加载三路固定 hook
            hook_src = open(HOOK_BUNDLE, encoding='utf-8').read()
            hook_script = session.create_script(hook_src)
            hook_script.on('message', on_msg)
            hook_script.load()
            print('hook script loaded on name=%s' % name, flush=True)
            break
        except Exception as e:
            print('attach retry %d: %s' % (attempt, str(e)[:140]), flush=True)
            try:
                if session: session.detach()
            except Exception:
                pass
            time.sleep(1)
    if hook_script is None:
        print('ERROR: gadget attach 失败')
        return 1

    # 4) 等 hook 装好（status 文件出现 INSTALLED）
    for _ in range(40):
        st = sh(dev, 'cat ' + HOOK_STATUS + ' 2>/dev/null').stdout.decode('utf-8', 'ignore')
        if 'INSTALLED' in st:
            print('three-way hook INSTALLED', flush=True)
            break
        time.sleep(0.25)
    else:
        print('WARN: hook status 未出现 INSTALLED（继续测试）', flush=True)
    dump_hook_status(dev, 'after load')

    # 5) 再加载 nativeSearch RPC（同一 session）
    rpc_src = open(RPC_BUNDLE, encoding='utf-8').read()
    rpc_script = session.create_script(rpc_src)
    rpc_script.on('message', on_msg)
    rpc_script.load()
    print('rpc script loaded ping=%s' % rpc_script.exports_sync.ping(), flush=True)

    # 6) 文本 + 图片回归
    call_native(rpc_script, TEXT_API, text_data('iphone'), 'text_iphone', out_dir)
    time.sleep(2)
    img_path = os.path.abspath(IMAGE)
    print('\nimage: %s exists=%s' % (img_path, os.path.exists(img_path)), flush=True)
    call_native(rpc_script, IMAGE_API, image_data(img_path, 'iphone'), 'image_iphone', out_dir)

    # 7) 抓命中计数与 1927
    time.sleep(2)
    dump_hook_status(dev, 'after search')
    dump_logcat_counts(dev, 'final')

    try:
        session.detach()
    except Exception:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
