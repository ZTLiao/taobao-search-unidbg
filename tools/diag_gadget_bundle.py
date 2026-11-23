#!/usr/bin/env python3
"""分步诊断 gadget 加载完整 RPC bundle 时在哪一段崩溃。

把 bundle 按关键标记切成若干段，逐段 create_script + load，
每段之间打印心跳，崩溃点即为最后成功加载的段之后。
"""
import os
import sys
import time

import frida

BUNDLE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      'frida', 'rpc_sign_bundle.js')
host = os.environ.get('FRIDA_GADGET_HOST', '127.0.0.1')
port = os.environ.get('FRIDA_GADGET_PORT', '27043')
addr = '%s:%s' % (host, port)

with open(BUNDLE, encoding='utf-8') as f:
    source = f.read()

print('[diag] bundle size=%d chars' % len(source))
print('[diag] connecting', addr)
dev = frida.get_device_manager().add_remote_device(addr)
session = dev.attach('Gadget')
print('[diag] attached')

msgs = []
def on_msg(m, d):
    if m.get('type') == 'send':
        msgs.append(m.get('payload'))
    if m.get('type') == 'error':
        print('[diag] SCRIPT ERROR:', m.get('description'))

# 完整加载，观察是否崩溃
print('[diag] loading FULL bundle...')
script = session.create_script(source)
script.on('message', on_msg)
try:
    script.load()
    print('[diag] FULL bundle loaded OK')
    # 尝试调用 status RPC
    time.sleep(1)
    exp = getattr(script, 'exports_sync', script.exports)
    print('[diag] calling status()...')
    st = exp.status()
    print('[diag] status =', str(st)[:500])
except Exception as e:
    print('[diag] LOAD/CALL FAILED:', type(e).__name__, str(e))
finally:
    try:
        script.unload()
    except Exception:
        pass
    try:
        session.detach()
    except Exception:
        pass
print('[diag] done; last msgs:', msgs[-10:])
