#!/usr/bin/env python3
"""Frida 真机签名 RPC 冒烟探针：加载 rpc_sign.js，打印 status/deviceInfo，签一个测试 INPUT。"""
import json
import os
import sys
import time

import frida

ROOT = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(ROOT, 'frida', 'rpc_sign_bundle.js')
PACKAGE = os.environ.get('FRIDA_PACKAGE', 'com.taobao.taobao')

TEST_INPUT = (
    'awJISchpPiMDADAJ3weNXszG&&&21646297'
    '&f8f124264d8437ae645551f73b3e5047'
    '&1795313584&mtop.taobao.wireless.home.newface.awesome.get&1.0'
    '&&231200@taobao_android_10.69.10'
    '&Aiw8S8YGCUMNCOMAFfPJIdq-Pyb4740VtErxvLS58KdE'
    '&37.42195&-122.084013&openappkey=DEFAULT_AUTH&27&&&&&&&'
)


def main():
    dev = frida.get_usb_device()
    pid = None
    procs = dev.enumerate_processes()
    print('MATCHING', [(p.pid, p.name) for p in procs if 'taobao' in p.name], flush=True)
    for p in procs:  # 优先主进程，Mtop/SecurityGuard 实例都在主进程
        if p.name == PACKAGE:
            pid = p.pid
            break
    if pid is None:
        for p in procs:
            if p.name.startswith(PACKAGE + ':'):
                pid = p.pid
                break
    if os.environ.get('FRIDA_PID'):
        pid = int(os.environ['FRIDA_PID'])
    if pid is None:
        pid = dev.spawn([PACKAGE])
        dev.resume(pid)
    print('attach pid=%s' % pid, flush=True)
    session = dev.attach(pid)
    with open(SCRIPT, encoding='utf-8') as f:
        source = f.read()
    script = session.create_script(source)
    script.on('message', lambda message, data: print('[frida]', message, flush=True))
    script.load()
    time.sleep(1)

    try:
        print('INSTANCES=', script.exports.debug_instances(), flush=True)
    except Exception as e:
        print('INSTANCES ERROR', e, flush=True)
    print('STATUS  =', script.exports.status(), flush=True)
    print('DEVICE  =', script.exports.device_info(), flush=True)

    payload = json.dumps({'input': TEST_INPUT, 'appKey': '21646297',
                          'api': 'mtop.taobao.wireless.home.newface.awesome.get'})
    inner = json.dumps({
        'api': 'mtop.relationrecommend.MtopRecommend.recommend',
        'version': '1.0',
        'params': {
            'utdid': 'awJISchpPiMDADAJ3weNXszG', 'uid': '', 'reqbiz-ext': '',
            'data': '{}', 't': str(int(time.time())),
            'api': 'mtop.relationrecommend.MtopRecommend.recommend', 'v': '1.0',
            'sid': '', 'ttid': '231200@taobao_android_10.69.10',
            'deviceId': 'Aiw8S8YGCUMNCOMAFfPJIdq-Pyb4740VtErxvLS58KdE',
            'lat': '37.42195', 'lng': '-122.084013',
            'extdata': 'openappkey=DEFAULT_AUTH', 'x-features': '27'
        }
    })
    try:
        print('SIGN_BY_INNER =', script.exports.sign_by_inner(inner), flush=True)
    except Exception as e:
        print('SIGN_BY_INNER ERROR', e, flush=True)
    try:
        print('SIGN_LEGACY_INNER =', script.exports.sign_legacy_by_inner(
            json.dumps({'s1': 'test-data', 's2': '21646297'})), flush=True)
    except Exception as e:
        print('SIGN_LEGACY_INNER ERROR', e, flush=True)
    for name in ('sign_request', 'sign_legacy'):
        try:
            print(name.upper(), '=', getattr(script.exports, name)(payload), flush=True)
        except Exception as e:
            print(name.upper(), 'ERROR', e, flush=True)
    session.detach()


if __name__ == '__main__':
    sys.exit(main())
