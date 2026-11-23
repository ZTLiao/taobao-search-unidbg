#!/usr/bin/env python3
"""验证 frida-gadget listen 模式连接是否可用（不依赖 ptrace / root）。

用法：
  # 先建立端口转发
  adb -s <serial> forward tcp:27043 tcp:27043
  # 再运行
  python tools/test_gadget_connection.py
  # 或自定义
  FRIDA_GADGET_HOST=127.0.0.1 FRIDA_GADGET_PORT=27043 python tools/test_gadget_connection.py
"""
import os
import sys

import frida

host = os.environ.get('FRIDA_GADGET_HOST', '127.0.0.1')
port = os.environ.get('FRIDA_GADGET_PORT', '27043')
want_name = os.environ.get('FRIDA_GADGET_NAME', 'Gadget')
addr = '%s:%s' % (host, port)

print('[test_gadget] connecting remote device:', addr)
dm = frida.get_device_manager()
dev = dm.add_remote_device(addr)
print('[test_gadget] remote device:', dev)

procs = dev.enumerate_processes()
print('[test_gadget] processes:', [(p.pid, p.name) for p in procs])

target = None
for p in procs:
    if p.name == want_name or want_name in p.name:
        target = p.name
        break
if target is None and procs:
    # gadget 默认进程名就是 Gadget；若被改过则取第一个
    target = procs[0].name
if target is None:
    print('[test_gadget] FAIL: no process to attach')
    sys.exit(2)

print('[test_gadget] attaching to:', target)
session = dev.attach(target)
print('[test_gadget] attached OK')
script = session.create_script(
    'rpc.exports.ping = function () { return 123; };'
)
script.on('message', lambda m, d: print('[test_gadget] msg:', m))
script.load()
ret = script.exports_sync.ping()
print('[test_gadget] ping() =', ret)
session.detach()
if ret == 123:
    print('[test_gadget] SUCCESS: gadget listen mode is reachable')
else:
    print('[test_gadget] UNEXPECTED ping result')
    sys.exit(3)
