#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SG 全量文件读取诊断：resume 模式尽早 attach，装 read_fulltrace，触发搜索抓读取路径。

用法: py -3 -u tools/diag_sg_read.py [serial] [--wait SEC]
"""
import os, sys, time, json, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ADB = 'C:/Users/pc/rea-tools/platform-tools/adb.exe'
HOOK = os.path.join(HERE, 'frida', 'sg_read_fulltrace_bundle.js')
RPC = os.path.join(HERE, 'frida', 'rpc_native_only_bundle.js')
STATUS = '/data/local/tmp/sg_readtrace_status.txt'
PORT = 27043
API = 'mtop.relationrecommend.MtopRecommend.recommend'
TTID = '231200@taobao_android_10.69.10'


def sh(dev, cmd, cap=True):
    return subprocess.run([ADB, '-s', dev, 'shell', cmd], capture_output=cap)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    wait_sec = 8
    if '--wait' in sys.argv:
        try: wait_sec = int(sys.argv[sys.argv.index('--wait') + 1])
        except Exception: pass
    dev = args[0] if args else subprocess.check_output([ADB, 'devices']).decode().split('device\n')[0].strip().splitlines()[-1]
    print('device:', dev, 'wait_sec:', wait_sec, flush=True)

    sh(dev, 'rm -f ' + STATUS)
    sh(dev, 'am force-stop com.taobao.taobao')
    time.sleep(2)
    sh(dev, 'logcat -c')
    subprocess.run([ADB, '-s', dev, 'forward', 'tcp:%d' % PORT, 'tcp:%d' % PORT], check=True)

    import frida
    gadget = frida.get_device_manager().add_remote_device('127.0.0.1:%d' % PORT)
    subprocess.Popen([ADB, '-s', dev, 'shell',
                      'am start -n com.taobao.taobao/com.taobao.tao.welcome.Welcome'],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print('launched, waiting %ds...' % wait_sec, flush=True)
    time.sleep(wait_sec)

    session = None
    for attempt in range(30):
        try:
            procs = gadget.enumerate_processes()
            if not procs: time.sleep(0.5); continue
            name = procs[0].name
            session = gadget.attach(name)
            def on_msg(m, d):
                if m['type'] in ('log', 'error'):
                    print('[FRIDA]', m.get('payload', m.get('description', m)), flush=True)
            hs = session.create_script(open(HOOK, encoding='utf-8').read())
            hs.on('message', on_msg); hs.load()
            print('hook attached name=%s' % name, flush=True)
            break
        except Exception as e:
            print('attach retry %d: %s' % (attempt, str(e)[:120]), flush=True)
            try:
                if session: session.detach()
            except Exception: pass
            time.sleep(1)
    if not session:
        print('ERROR attach failed'); return 1

    # 触发一次文本搜索
    rs = session.create_script(open(RPC, encoding='utf-8').read())
    rs.on('message', on_msg); rs.load()
    data = json.dumps({"requestAlias":"wsearch","isEnterSrpSearch":"true","appId":"66",
                       "q":"iphone","n":"20","page":"1"}, ensure_ascii=False, separators=(',', ':'))
    req = {"api":API,"version":"1.0","data":data,"ttid":TTID,"method":"POST","headers":{}}
    print('triggering nativeSearch...', flush=True)
    try:
        r = rs.exports_sync.native_search(json.dumps(req, ensure_ascii=False))
        print('search ret:', str(r)[:300], flush=True)
    except Exception as e:
        print('search err:', str(e)[:300], flush=True)
    time.sleep(3)

    print('\n===== SG READ TRACE =====', flush=True)
    st = sh(dev, 'cat ' + STATUS + ' 2>/dev/null').stdout.decode('utf-8', 'ignore')
    print(st if st else '(empty)', flush=True)
    print('===== 1927 count =====', flush=True)
    logs = subprocess.run([ADB, '-s', dev, 'logcat', '-d'], capture_output=True).stdout.decode('utf-8', 'ignore')
    print('1927:', logs.count('1927'), flush=True)
    try: session.detach()
    except Exception: pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
