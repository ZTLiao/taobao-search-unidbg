#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fopen 重定向破解 1927 回归测试：装 sg_fopen_redirect hook + nativeSearch，跑文本/图片。

用法: py -3 -u tools/regression_fopen.py <serial> [--wait SEC]
"""
import os, sys, time, json, base64, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ADB = 'C:/Users/pc/rea-tools/platform-tools/adb.exe'
HOOK = os.path.join(HERE, 'frida', 'sg_fopen_redirect_bundle.js')
RPC = os.path.join(HERE, 'frida', 'rpc_native_only_bundle.js')
IMAGE = os.path.join(HERE, 'assets', 'iphone18.jpg')
HOOK_STATUS = '/data/local/tmp/sg_fopen_status.txt'
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
    print('\n========== %s ==========' % label, flush=True)
    try:
        r=script.exports_sync.native_search(json.dumps(req, ensure_ascii=False))
        out=json.loads(r) if isinstance(r,str) else r
        print('retCode=%s retMsg=%s' % (out.get('retCode'),out.get('retMsg')))
        print('instance=%s score=%s step=%s error=%s' % (
            out.get('instanceId'),out.get('instanceScore'),out.get('step'),out.get('error')))
        ds=out.get('data') or ''
        print('data.len=%d head=%s' % (len(ds),ds[:500]))
        real=any(k in ds.lower() for k in ('item','title','price','auction','rawtitle'))
        risk=any(k in ds for k in ('USER_VALIDATE','RGV587','FAIL_SYS',' punish','LOGIN'))
        print('>>> 判定: real_items=%s risk=%s' % (real,risk), flush=True)
        with open(os.path.join(HERE,'..','regression_fopen_%s.json'%label),'w',encoding='utf-8') as f:
            json.dump(out,f,ensure_ascii=False,indent=1)
        return out
    except Exception as e:
        print('调用异常:',str(e)[:500],flush=True); return None


def main():
    args=[a for a in sys.argv[1:] if not a.startswith('--')]
    wait=8
    if '--wait' in sys.argv:
        try: wait=int(sys.argv[sys.argv.index('--wait')+1])
        except: pass
    dev=args[0] if args else subprocess.check_output([ADB,'devices']).decode().split('device\n')[0].strip().splitlines()[-1]
    print('device:',dev,'wait:',wait,flush=True)
    sh(dev,'rm -f '+HOOK_STATUS)
    sh(dev,'am force-stop com.taobao.taobao'); time.sleep(2); sh(dev,'logcat -c')
    subprocess.run([ADB,'-s',dev,'forward','tcp:%d'%PORT,'tcp:%d'%PORT],check=True)
    import frida
    gadget=frida.get_device_manager().add_remote_device('127.0.0.1:%d'%PORT)
    subprocess.Popen([ADB,'-s',dev,'shell','am start -n com.taobao.taobao/com.taobao.tao.welcome.Welcome'],
                     stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    print('launching, wait %ds...'%wait,flush=True); time.sleep(wait)
    session=None
    def on_msg(m,d):
        if m['type'] in ('log','error'):
            print('[FRIDA]',m.get('payload',m.get('description',m)),flush=True)
    for attempt in range(30):
        try:
            procs=gadget.enumerate_processes()
            if not procs: time.sleep(0.5); continue
            name=procs[0].name
            session=gadget.attach(name)
            hs=session.create_script(open(HOOK,encoding='utf-8').read())
            hs.on('message',on_msg); hs.load()
            print('hook attached name=%s'%name,flush=True)
            break
        except Exception as e:
            print('attach retry %d: %s'%(attempt,str(e)[:120]),flush=True)
            try:
                if session: session.detach()
            except: pass
            time.sleep(1)
    if not session:
        print('ERROR attach failed'); return 1
    time.sleep(1)
    rs=session.create_script(open(RPC,encoding='utf-8').read())
    rs.on('message',on_msg); rs.load()
    print('rpc ping=%s'%rs.exports_sync.ping(),flush=True)
    call(rs,TEXT_API,text_data('iphone'),'text_iphone')
    time.sleep(2)
    img=os.path.abspath(IMAGE)
    print('\nimage exists=%s'%os.path.exists(img),flush=True)
    call(rs,IMAGE_API,image_data(img,'iphone'),'image_iphone')
    time.sleep(2)
    print('\n===== hook status =====',flush=True)
    print(sh(dev,'cat '+HOOK_STATUS+' 2>/dev/null').stdout.decode('utf-8','ignore'),flush=True)
    print('===== logcat counts =====',flush=True)
    logs=subprocess.run([ADB,'-s',dev,'logcat','-d'],capture_output=True).stdout.decode('utf-8','ignore')
    print('1927:',logs.count('1927'),'EC40002:',logs.count('EC40002'),
          'SIGN_ERROR:',logs.count('ANDROID_SYS_GENERATE_MTOP_SIGN_ERROR'),
          'USER_VALIDATE:',logs.count('USER_VALIDATE'),flush=True)
    try: session.detach()
    except: pass
    return 0


if __name__=='__main__':
    sys.exit(main())
