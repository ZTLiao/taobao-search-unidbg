#!/usr/bin/env python3
"""race-attach + native open hook：诊断/破解 SG 1927 的 native 层签名读取。

两种模式（用 --redirect 切换，共用同一 bundle 与同一 gadget on_load=wait 流程）：

  PROBE（默认）：
    dump SG 启动期所有命中 APK/签名关键字的 open/openat（path/flags/tid/fd）。
    确认 SG 到底打开了哪个重打包 base.apk 路径。

  REDIRECT（--redirect）：
    在 adb shell 里 touch /data/local/tmp/sg_open_redirect.flag，
    脚本在 onEnter 把重打包 base.apk 的路径替换为
    /data/local/tmp/official_base.apk（官方签名 APK），
    让 SG 读到官方证书 -> 解密安全图片成功 -> 1927 消失。

用法：
  python3 tools/race_attach_native_open.py [设备serial] [--redirect]
"""
import os
import sys
import time
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ADB = 'C:/Users/pc/rea-tools/platform-tools/adb.exe'
BUNDLE = os.path.join(HERE, 'frida', 'sg_native_open_hook_bundle.js')
GADGET_PORT = 27043
STATUS_FILE = '/data/local/tmp/sg_native_open_status.txt'
REDIRECT_FLAG = '/data/local/tmp/sg_open_redirect.flag'


def sh(dev, cmd, capture=True):
    return subprocess.run([ADB, '-s', dev, 'shell', cmd],
                          capture_output=capture)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    redirect = '--redirect' in sys.argv
    dev = args[0] if args else subprocess.check_output(
        [ADB, 'devices']).decode().split('device\n')[0].strip().splitlines()[-1]
    print('device:', dev, 'mode:', 'REDIRECT' if redirect else 'PROBE')

    # 0) 开关 & 清理
    if redirect:
        sh(dev, 'touch ' + REDIRECT_FLAG)
    else:
        sh(dev, 'rm -f ' + REDIRECT_FLAG)
    sh(dev, 'rm -f ' + STATUS_FILE)
    sh(dev, 'am force-stop com.taobao.taobao')
    time.sleep(2)
    sh(dev, 'logcat -c')

    # 1) 端口转发
    subprocess.run([ADB, '-s', dev, 'forward', 'tcp:%d' % GADGET_PORT,
                    'tcp:%d' % GADGET_PORT], check=True)

    import frida
    mgr = frida.get_device_manager()
    gadget = mgr.add_remote_device('127.0.0.1:%d' % GADGET_PORT)

    # 2) 启动 App —— gadget 在 loadLibrary 时暂停（on_load=wait）
    print('launching app (gadget pauses at loadLibrary)...')
    subprocess.Popen([ADB, '-s', dev, 'shell',
                      'am start -n com.taobao.taobao/com.taobao.tao.welcome.Welcome'],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 3) 轮询 attach gadget
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

    # 4) 加载 native open hook bundle
    src = open(BUNDLE, encoding='utf-8').read()
    script = session.create_script(src)

    def on_msg(msg, data):
        if msg['type'] in ('log', 'error'):
            print('[FRIDA]', msg.get('payload', msg.get('description', msg)))

    script.on('message', on_msg)
    script.load()
    print('native open hook loaded')

    # 5) 等 hook 装好（文件标记里出现 'installed'）
    for _ in range(40):
        st = sh(dev, 'cat ' + STATUS_FILE + ' 2>/dev/null').stdout.decode('utf-8', 'ignore')
        if 'hooks installed' in st or 'installed=true' in st:
            print('hook installed')
            break
        time.sleep(0.25)

    # 6) resume 放行 App
    try:
        session.resume()
        print('resumed app via session.resume()')
    except Exception as e:
        print('resume failed:', e)

    # 7) 观察窗口
    time.sleep(15)

    print('\n=== native open status ===')
    print(sh(dev, 'cat ' + STATUS_FILE + ' 2>/dev/null').stdout.decode('utf-8', 'ignore'))
    print('=== 1927 count ===')
    logs = subprocess.run([ADB, '-s', dev, 'logcat', '-d'],
                          capture_output=True).stdout.decode('utf-8', 'ignore')
    print('1927 occurrences:', logs.count('errorCode 1927'))
    print('EC40002 occurrences:', logs.count('EC40002'))

    try:
        session.detach()
    except Exception:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
