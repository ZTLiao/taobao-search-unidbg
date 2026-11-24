#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""最小 attach + 加载指定 bundle + 触发搜索。用法: py -3 -u diag_memdump.py <bundle> [serial] [--wait SEC]"""
import os, sys, time, subprocess
HERE = os.path.dirname(os.path.abspath(__file__))
ADB = 'C:/Users/pc/rea-tools/platform-tools/adb.exe'
PORT = 27043
STATUS = '/data/local/tmp/sg_memdump_status.txt'

def sh(dev, cmd, cap=True):
    return subprocess.run([ADB,'-s',dev,'shell',cmd],capture_output=cap)

def main():
    bundle = sys.argv[1]
    args = [a for a in sys.argv[2:] if not a.startswith('--')]
    wait = 8
    if '--wait' in sys.argv:
        try: wait=int(sys.argv[sys.argv.index('--wait')+1])
        except: pass
    dev = args[0] if args else None
    if not dev:
        out=subprocess.check_output([ADB,'devices']).decode()
        for line in out.splitlines():
            if '\tdevice' in line: dev=line.split()[0]; break
    print('dev:',dev,'bundle:',bundle,flush=True)
    sh(dev,'rm -f '+STATUS)
    sh(dev,'am force-stop com.taobao.taobao'); time.sleep(2); sh(dev,'logcat -c')
    subprocess.run([ADB,'-s',dev,'forward','tcp:%d'%PORT,'tcp:%d'%PORT],check=True)
    import frida
    gadget=frida.get_device_manager().add_remote_device('127.0.0.1:%d'%PORT)
    subprocess.Popen([ADB,'-s',dev,'shell','am start -n com.taobao.taobao/com.taobao.tao.welcome.Welcome'],
                     stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if '--race' in sys.argv:
        print('race mode: attach ASAP (no fixed wait)',flush=True)
    else:
        print('waiting %ds'%wait,flush=True); time.sleep(wait)
    for att in range(30):
        try:
            procs=gadget.enumerate_processes()
            if not procs: time.sleep(0.5); continue
            sess=gadget.attach(procs[0].name)
            def on_msg(m,d):
                if m['type'] in ('log','error'):
                    print('[F]',m.get('payload',m.get('description',m)),flush=True)
            sc=sess.create_script(open(bundle,encoding='utf-8').read())
            sc.on('message',on_msg); sc.load()
            print('loaded',flush=True)
            break
        except Exception as e:
            print('retry %d: %s'%(att,str(e)[:100]),flush=True); time.sleep(1)
    else:
        print('attach failed'); return 1
    if '--search' in sys.argv:
        import json
        settle = 0
        if '--settle' in sys.argv:
            try: settle=int(sys.argv[sys.argv.index('--settle')+1])
            except: pass
        if settle:
            print('settle %ds before search'%settle,flush=True); time.sleep(settle)
        # 先读 hook 脚本自己的 status
        try:
            print('hook status RPC:', str(sc.exports_sync.status())[:1500], flush=True)
        except Exception as e:
            print('hook status err', str(e)[:100], flush=True)
        rpc_bundle = os.path.join(HERE, 'frida', 'rpc_native_only_bundle.js')
        rs = sess.create_script(open(rpc_bundle, encoding='utf-8').read())
        rs.on('message', on_msg); rs.load()
        print('rpc ping=%s' % rs.exports_sync.ping(), flush=True)
        req = {"api":"mtop.relationrecommend.MtopRecommend.recommend","version":"1.0",
               "data":json.dumps({"requestAlias":"wsearch","isEnterSrpSearch":"true","appId":"66",
                                  "q":"iphone","n":"20","page":"1"},ensure_ascii=False,separators=(',',':')),
               "ttid":"231200@taobao_android_10.69.10","method":"POST","headers":{}}
        try:
            print('search:', str(rs.exports_sync.native_search(json.dumps(req,ensure_ascii=False)))[:200], flush=True)
        except Exception as e:
            print('search err', str(e)[:150], flush=True)
        time.sleep(2)
        try:
            print('hook status AFTER search:', str(sc.exports_sync.status())[:2000], flush=True)
        except Exception as e:
            print('hook status after err', str(e)[:100], flush=True)
    time.sleep(3)
    print('\n=== status ===',flush=True)
    print(sh(dev,'cat '+STATUS+' 2>/dev/null').stdout.decode('utf-8','ignore')[:5000],flush=True)
    try: sess.detach()
    except: pass
    return 0

if __name__=='__main__':
    sys.exit(main())
