#!/usr/bin/env python3
"""通用 race-attach：gadget on_load=wait 暂停 App，attach 后加载任意 bundle 再 resume。

用法：
  python3 tools/race_attach_bundle.py <bundle路径> [设备serial] [--status <设备状态文件>]
  python3 tools/race_attach_bundle.py tools/frida/sg_read_trace_bundle.js 192.168.11.38:37909 \
      --status /data/local/tmp/sg_read_trace_status.txt
"""
import os
import sys
import time
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ADB = 'C:/Users/pc/rea-tools/platform-tools/adb.exe'
GADGET_PORT = 27043


def sh(dev, cmd):
    return subprocess.run([ADB, '-s', dev, 'shell', cmd], capture_output=True)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    status_file = None
    if '--status' in sys.argv:
        status_file = sys.argv[sys.argv.index('--status') + 1]

    bundle = args[0]
    dev = args[1] if len(args) > 1 else subprocess.check_output(
        [ADB, 'devices']).decode().split('device\n')[0].strip().splitlines()[-1]
    print('device:', dev, 'bundle:', os.path.basename(bundle))

    if status_file:
        sh(dev, 'rm -f ' + status_file)
    sh(dev, 'am force-stop com.taobao.taobao')
    time.sleep(2)
    sh(dev, 'logcat -c')

    subprocess.run([ADB, '-s', dev, 'forward', 'tcp:%d' % GADGET_PORT,
                    'tcp:%d' % GADGET_PORT], check=True)

    import frida
    mgr = frida.get_device_manager()
    gadget = mgr.add_remote_device('127.0.0.1:%d' % GADGET_PORT)

    print('launching app...')
    subprocess.Popen([ADB, '-s', dev, 'shell',
                      'am start -n com.taobao.taobao/com.taobao.tao.welcome.Welcome'],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    session = None
    for _ in range(60):
        try:
            procs = gadget.enumerate_processes()
            if procs:
                print('gadget process found:', [(p.pid, p.name) for p in procs])
                session = gadget.attach(procs[0].pid)
                break
        except Exception:
            pass
        time.sleep(0.5)
    if session is None:
        print('ERROR: gadget not reachable')
        return 1

    src = open(bundle, encoding='utf-8').read()
    script = session.create_script(src)

    def on_msg(msg, data):
        if msg['type'] in ('log', 'error'):
            print('[FRIDA]', msg.get('payload', msg.get('description', msg)))

    script.on('message', on_msg)
    script.load()
    print('bundle loaded')

    try:
        session.resume()
        print('resumed app')
    except Exception as e:
        print('resume failed:', e)

    time.sleep(15)

    if status_file:
        print('\n=== status file ===')
        print(sh(dev, 'cat ' + status_file + ' 2>/dev/null').stdout.decode('utf-8', 'ignore'))
    logs = subprocess.run([ADB, '-s', dev, 'logcat', '-d'],
                          capture_output=True).stdout.decode('utf-8', 'ignore')
    print('1927 occurrences:', logs.count('errorCode 1927'))

    try:
        session.detach()
    except Exception:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
