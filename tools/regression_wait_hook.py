#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wait 模式两阶段破解：
阶段1 App 启动被 gadget(on_load=wait) 暂停 → attach → 装 fopen/svc hook → resume 放行，
      让 SG 启动期读到官方 APK 签名（authCode 正确）。
阶段2 resume 后重新 attach（gadget listener 常驻）→ 装 nativeSearch RPC → 文本/图片回归。

用法: py -3 -u tools/regression_wait_hook.py [serial]
"""
import os, sys, time, json, base64, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ADB = 'C:/Users/pc/rea-tools/platform-tools/adb.exe'
# 阶段1：启动期装两个 hook（fopen 重定向 + svc 透传重定向），合并到一个 script
HOOK_FOPEN = os.path.join(HERE, 'frida', 'sg_fopen_redirect_bundle.js')
HOOK_SVC = os.path.join(HERE, 'frida', 'sg_syscall_replace_bundle.js')
RPC = os.path.join(HERE, 'frida', 'rpc_native_only_bundle.js')
IMAGE = os.path.join(HERE, 'assets', 'iphone18.jpg')
STATUS_FOPEN = '/data/local/tmp/sg_fopen_status.txt'
STATUS_SVC = '/data/local/tmp/sg_syscall_status.txt'
MODEF = '/data/local/tmp/sg_syscall_mode.txt'
PORT = 27043
TEXT_API = 'mtop.relationrecommend.MtopRecommend.recommend'
IMAGE_API = 'mtop.relationrecommend.PailitaoRecommend.recommend'
TTID = '231200@taobao_android_10.69.10'


def sh(dev, cmd, cap=True):
    return subprocess.run([ADB, '-s', dev, 'shell', cmd], capture_output=cap)


def text_data(q='iphone'):
    return json.dumps({"requestAlias":"wsearch","isEnterSrpSearch":"true","appId":"66",
                       "q":q,"n":"20","page":"1"}, ensure_ascii=False, separators=(',',':'))


def image_data(path, q='iphone'):
    p={"region":"full","full_region_size":"full","biz_type":"pai","subSearchType":"imageText_v3",
       "m":"api4etao","n":"60","appId":"32969","_sid_":"69148","scene":"multiObject",
       "page":1,"from":"","pssource":"sy",
       "extraParams":"use_multi_cat:1;use_pid_summary:1;cat_deleted:1;use_pid_tag:1;extend_count:3"}
    if os.path.exists(path):
        with open(path,'rb') as f: p['strimg']=base64.b64encode(f.read()).decode('ascii')
    if q: p['q']=q
    inner=json.dumps(p, ensure_ascii=False, separators=(',',':'))
    return json.dumps({"params":inner,"appId":"32969"}, ensure_ascii=False, separators=(',',':'))


def call(script, api, data, label):
    req={"api":api,"version":"1.0","data":data,"ttid":TTID,"method":"POST","headers":{}}
    print('\n===== %s ====='%label, flush=True)
    try:
        r=script.exports_sync.native_search(json.dumps(req,ensure_ascii=False))
        out=json.loads(r) if isinstance(r,str) else r
        print('retCode=%s retMsg=%s'%(out.get('retCode'),out.get('retMsg')))
        ds=out.get('data') or ''
        print('instance=%s data.len=%d head=%s'%(out.get('instanceId'),len(ds),ds[:400]))
        real=any(k in ds.lower() for k in ('item','title','price','auction','rawtitle'))
        risk=any(k in ds for k in ('USER_VALIDATE','RGV587','FAIL_SYS',' punish','LOGIN'))
        print('>>> real_items=%s risk=%s'%(real,risk), flush=True)
        with open(os.path.join(HERE,'..','regression_wait_%s.json'%label),'w',encoding='utf-8') as f:
            json.dump(out,f,ensure_ascii=False,indent=1)
        return out
    except Exception as e:
        print('调用异常:',str(e)[:400],flush=True); return None


def main():
    args=[a for a in sys.argv[1:] if not a.startswith('--')]
    dev=args[0] if args else None
    if not dev:
        out=subprocess.check_output([ADB,'devices']).decode()
        for line in out.splitlines():
            if '\tdevice' in line: dev=line.split()[0]; break
    print('device:',dev,flush=True)

    # 模式：fopen 一定 REDIRECT；svc 用 REDIRECT
    sh(dev,'echo -n REDIRECT > '+MODEF)
    sh(dev,'rm -f '+STATUS_FOPEN+' '+STATUS_SVC)
    sh(dev,'am force-stop com.taobao.taobao'); time.sleep(2)
    sh(dev,'logcat -c')
    subprocess.run([ADB,'-s',dev,'forward','tcp:%d'%PORT,'tcp:%d'%PORT],check=True)
    import frida
    gadget=frida.get_device_manager().add_remote_device('127.0.0.1:%d'%PORT)

    def on_msg(m,d):
        if m['type'] in ('log','error'):
            print('[F]',m.get('payload',m.get('description',m)),flush=True)

    # 阶段1：启动 App（gadget wait 暂停）
    print('[phase1] launching app (gadget pauses at loadLibrary)...',flush=True)
    subprocess.Popen([ADB,'-s',dev,'shell','am start -n com.taobao.taobao/com.taobao.tao.welcome.Welcome'],
                     stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    session=None; scripts=[]
    for att in range(60):
        try:
            procs=gadget.enumerate_processes()
            if not procs: time.sleep(0.5); continue
            session=gadget.attach(procs[0].pid)
            print('[phase1] attached pid=%s'%procs[0].pid,flush=True)
            break
        except Exception as e:
            time.sleep(0.5)
    if not session:
        print('[phase1] attach failed'); return 1
    # 装 fopen 重定向 hook
    try:
        s1=session.create_script(open(HOOK_FOPEN,encoding='utf-8').read())
        s1.on('message',on_msg); s1.load(); scripts.append(s1)
        print('[phase1] fopen hook loaded',flush=True)
    except Exception as e:
        print('[phase1] fopen hook err',str(e)[:200],flush=True)
    # 装 svc 透传重定向 hook
    try:
        s2=session.create_script(open(HOOK_SVC,encoding='utf-8').read())
        s2.on('message',on_msg); s2.load(); scripts.append(s2)
        print('[phase1] svc hook loaded',flush=True)
    except Exception as e:
        print('[phase1] svc hook err',str(e)[:200],flush=True)
    time.sleep(1)
    # resume 放行
    try:
        session.resume(); print('[phase1] resumed app',flush=True)
    except Exception as e:
        print('[phase1] resume err',str(e)[:200],flush=True)
    # 等 SG 启动期初始化完成
    print('[phase1] waiting 20s for SG init...',flush=True)
    time.sleep(20)
    print('[phase1] fopen status:',sh(dev,'cat '+STATUS_FOPEN+' 2>/dev/null').stdout.decode('utf-8','ignore')[:1500],flush=True)
    print('[phase1] svc status:',sh(dev,'cat '+STATUS_SVC+' 2>/dev/null').stdout.decode('utf-8','ignore')[:1500],flush=True)

    # 阶段2：重新 attach 做 nativeSearch
    print('[phase2] re-attach for nativeSearch...',flush=True)
    session2=None
    for att in range(30):
        try:
            procs=gadget.enumerate_processes()
            if not procs: time.sleep(1); continue
            session2=gadget.attach(procs[0].name)
            rs=session2.create_script(open(RPC,encoding='utf-8').read())
            rs.on('message',on_msg); rs.load()
            print('[phase2] attached ping=%s'%rs.exports_sync.ping(),flush=True)
            break
        except Exception as e:
            print('[phase2] retry %d: %s'%(att,str(e)[:100]),flush=True); time.sleep(1)
    if not session2:
        print('[phase2] attach failed'); return 1
    call(rs,TEXT_API,text_data('iphone'),'text_iphone')
    time.sleep(2)
    call(rs,IMAGE_API,image_data(os.path.abspath(IMAGE),'iphone'),'image_iphone')
    time.sleep(2)
    print('\n===== logcat counts =====',flush=True)
    logs=subprocess.run([ADB,'-s',dev,'logcat','-d'],capture_output=True).stdout.decode('utf-8','ignore')
    print('1927:',logs.count('1927'),'EC40002:',logs.count('EC40002'),
          'SIGN_ERROR:',logs.count('ANDROID_SYS_GENERATE_MTOP_SIGN_ERROR'),
          'USER_VALIDATE:',logs.count('USER_VALIDATE'),flush=True)
    try: session2.detach()
    except: pass
    return 0


if __name__=='__main__':
    sys.exit(main())
