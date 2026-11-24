#!/usr/bin/env python3
"""race-attach：利用 gadget on_load=wait 暂停 App，在 SG 初始化前装好签名 spoof hook。

原理：
  - gadget config 用 listen + on_load="wait"，loadLibrary 时暂停主线程，
    直到外部 attach 并 resume。
  - 本脚本启动 App 后立即 attach 'Gadget'，加载 sg_sigspoof_bundle.js
    （hook getPackageInfo 返回官方证书），然后 resume。
  - SG 初始化发生在 invoke-super onCreate 之后，此时 hook 已就位，
    SG 读到官方证书 → 安全图片解密成功 → authCode 正常 → 1927 消失。

用法（真机 WiFi adb）：
  python3 tools/race_attach_sg_spoof.py [设备serial]
"""
import os
import sys
import time
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
ADB = 'C:/Users/pc/rea-tools/platform-tools/adb.exe'
PYFRIDA = 'C:/Users/pc/.pyenv/pyenv-win/versions/3.11.9/python.exe'
BUNDLE = os.path.join(HERE, 'frida', 'sg_sigspoof_bundle.js')
GADGET_PORT = 27043


def main():
    dev = sys.argv[1] if len(sys.argv) > 1 else subprocess.check_output(
        [ADB, 'devices']).decode().split('device\n')[0].strip().splitlines()[-1]
    print('device:', dev)

    # 1) 端口转发
    subprocess.run([ADB, '-s', dev, 'forward', 'tcp:%d' % GADGET_PORT,
                    'tcp:%d' % GADGET_PORT], check=True)

    import frida
    mgr = frida.get_device_manager()
    gadget = mgr.add_remote_device('127.0.0.1:%d' % GADGET_PORT)

    # 2) 清状态、强停、清日志
    subprocess.run([ADB, '-s', dev, 'shell',
                    'rm -f /data/local/tmp/sg_spoof_status.txt'], capture_output=True)
    subprocess.run([ADB, '-s', dev, 'shell', 'am force-stop com.taobao.taobao'])
    time.sleep(2)
    subprocess.run([ADB, '-s', dev, 'logcat', '-c'], capture_output=True)

    # 3) 启动 App —— gadget 会在 loadLibrary 时暂停（on_load=wait）
    print('launching app (gadget should pause at loadLibrary)...')
    subprocess.Popen([ADB, '-s', dev, 'shell',
                      'am start -n com.taobao.taobao/com.taobao.tao.welcome.Welcome'],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 4) 轮询等待 gadget 出现（最多 30 秒）
    session = None
    for i in range(60):
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

    # 5) 加载 hook 脚本
    src = open(BUNDLE, encoding='utf-8').read()
    script = session.create_script(src)

    def on_msg(msg, data):
        if msg['type'] in ('log', 'error'):
            print('[FRIDA]', msg.get('payload', msg.get('description', msg)))

    script.on('message', on_msg)
    script.load()
    print('hook script loaded, waiting hook installed...')

    # 6) 等 hook 装好（status.installed），从文件标记读
    for i in range(40):
        st = subprocess.run([ADB, '-s', dev, 'shell',
                             'cat /data/local/tmp/sg_spoof_status.txt 2>/dev/null'],
                            capture_output=True).stdout.decode('utf-8', 'ignore')
        if 'INSTALLED' in st or 'HIT' in st:
            print('hook installed:', st.strip().splitlines()[-1])
            break
        time.sleep(0.25)

    # 7) resume —— 放行 App 继续启动，SG 初始化此时会读到官方签名
    # gadget wait 模式下 attach 后必须显式 session.resume()
    try:
        session.resume()
        print('resumed app via session.resume()')
    except Exception as e:
        print('resume failed:', e)

    # 8) 保持连接，观察签名是否成功
    time.sleep(20)
    print('=== status file ===')
    print(subprocess.run([ADB, '-s', dev, 'shell',
                          'cat /data/local/tmp/sg_spoof_status.txt 2>/dev/null'],
                         capture_output=True).stdout.decode('utf-8', 'ignore'))
    print('=== 1927 count ===')
    logs = subprocess.run([ADB, '-s', dev, 'logcat', '-d'],
                          capture_output=True).stdout.decode('utf-8', 'ignore')
    print('1927 occurrences:', logs.count('errorCode 1927'))
    session.detach()
    return 0


if __name__ == '__main__':
    sys.exit(main())
