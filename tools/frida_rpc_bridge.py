#!/usr/bin/env python3
"""真机 signRequest HTTP 桥接服务。

把 Frida 注入淘宝主进程后暴露的 RPC 签名能力包装成 HTTP 接口，
供 SpringBoot 工程的 RpcMtopSigner 直接通过 sign.rpc.url 使用。

    POST /api/sign      -> 真机四头 {x-sign, x-sgext, x-mini-wua, x-umt, ...}
    POST /api/sign/legacy -> 老协议单串 {sign: ...}
    GET  /health        -> 组件就绪状态
    GET  /device        -> 真机设备身份（utdid/deviceId/ttid/umt 等）
    GET  /capture       -> 最近一次 App 真实签名入参/出参（诊断用）

前置条件：
  - adb 可见模拟器/真机，frida-server 正在运行
  - 淘宝 App 已安装并至少启动过一次（Mtop/SecurityGuard 已初始化）
  - python3 -m pip install frida

启动：
  python3 tools/frida_rpc_bridge.py --port 9091
  # 或指定 pid / 设备
  FRIDA_PID=4764 python3 tools/frida_rpc_bridge.py

工程侧配置：
  search.sign-backend=rpc
  sign.rpc.url=http://127.0.0.1:9091/api/sign
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import frida

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE = os.path.join(HERE, 'frida', 'rpc_sign_bundle.js')
DEFAULT_PACKAGE = 'com.taobao.taobao'

_state = {
    'session': None,
    'script': None,
    'pid': None,
    'error': '',
}
_lock = threading.RLock()


def log(msg):
    print('[frida-rpc-bridge] %s' % msg, flush=True)


def adb_path():
    for p in ('adb', os.path.expanduser('~/.local/android/sdk/platform-tools/adb')):
        try:
            subprocess.run([p, 'version'], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=True, timeout=3)
            return p
        except Exception:
            pass
    return None


def resolve_pid(dev, package):
    """优先主进程；Frida 有时只列出 :channel，故用 adb pidof 兜底。"""
    for p in dev.enumerate_processes():
        if p.name == package:
            return p.pid
    adb = adb_path()
    if adb:
        try:
            out = subprocess.check_output([adb, 'shell', 'pidof', package],
                                          stderr=subprocess.DEVNULL, timeout=5)
            pids = [int(x) for x in out.decode().split() if x.isdigit()]
            if pids:
                return pids[0]
        except Exception:
            pass
    for p in dev.enumerate_processes():
        if p.name.startswith(package + ':'):
            return p.pid
    return None


def connect(package, pid_override=None):
    with _lock:
        if _state['script'] is not None:
            return _state['script']
        device_id = os.environ.get('FRIDA_DEVICE')
        dev = frida.get_usb_device() if not device_id else frida.get_device(device_id)
        pid = pid_override or os.environ.get('FRIDA_PID')
        if pid:
            pid = int(pid)
        elif os.environ.get('FRIDA_SPAWN') == '1':
            # 从进程启动就注入：SecurityGuard 初始化命令（如 70102）只在早期出现
            pid = dev.spawn([package])
            dev.resume(pid)
        else:
            pid = resolve_pid(dev, package)
        if not pid:
            raise RuntimeError('未找到 %s 进程（可设置 FRIDA_PID）' % package)
        session = dev.attach(pid)
        with open(BUNDLE, encoding='utf-8') as f:
            source = f.read()
        script = session.create_script(source)
        def _on_msg(m, d):
            try:
                log('frida: %s' % json.dumps(m, ensure_ascii=False, default=str))
            except Exception:
                pass
        script.on('message', _on_msg)
        script.load()
        _state['session'] = session
        _state['script'] = script
        _state['pid'] = pid
        _state['error'] = ''
        log('attached pid=%s, bundle loaded' % pid)
        return script


def disconnect():
    with _lock:
        try:
            if _state['script']:
                _state['script'].unload()
        except Exception:
            pass
        try:
            if _state['session']:
                _state['session'].detach()
        except Exception:
            pass
        _state['script'] = None
        _state['session'] = None


def rpc(name, *args):
    with _lock:
        try:
            # 不要把缓存的 _state['pid'] 当 override 传回 connect：淘宝 App 可能重启
            # （风控页/被杀），旧 PID 会失效且 disconnect 不清 pid -> 永久 attach 失败。
            # 让 connect 每次自动 resolve 当前 PID；仅 FRIDA_PID 环境变量才固定 PID。
            script = connect(_state.get('package', DEFAULT_PACKAGE))
            # 用 exports_sync：所有 RPC 都是同步语义（nativeSearch 内含阻塞式
            # syncRequest()），异步 exports 在 Frida 17 会返回 promise 导致调用链错乱。
            exp = getattr(script, 'exports_sync', script.exports)
            return getattr(exp, name)(*args)
        except Exception as e:
            _state['error'] = str(e)
            disconnect()
            # 淘宝 App 可能刚重启，旧 session/pid 失效；断开后用新 PID 重建再试一次。
            try:
                script = connect(_state.get('package', DEFAULT_PACKAGE))
                exp = getattr(script, 'exports_sync', script.exports)
                return getattr(exp, name)(*args)
            except Exception as e2:
                _state['error'] = str(e2)
                disconnect()
                raise e2


def rpc_json(name, *args):
    raw = rpc(name, *args)
    if isinstance(raw, (dict, list)):
        return raw
    try:
        return json.loads(raw)
    except Exception:
        return {'error': 'RPC 返回非 JSON: %s' % raw}


def build_input(ctx, appkey, t, api, version, data):
    """与 SignContext.buildInput() 一致的 22 段 INPUT（桥接服务兜底用）。"""
    if not ctx:
        return ''
    md5 = hashlib.md5((data or '').encode('utf-8')).hexdigest()
    fields = [
        ctx.get('utdid', ''), ctx.get('uid', ''), '', str(appkey), md5, str(t),
        api, version, ctx.get('sid', ''), ctx.get('ttid', ''), ctx.get('deviceId', ''),
        ctx.get('lat', ''), ctx.get('lng', ''),
        ctx.get('extdata', 'openappkey=DEFAULT_AUTH'),
        str(ctx.get('xFeatures', ctx.get('x-features', '27'))),
    ]
    return '&'.join(fields) + '&' * 7


def sign_payload(body):
    api = str(body.get('api') or '')
    version = str(body.get('version') or '1.0')
    appkey = str(body.get('appKey') or '21646297')
    t = str(body.get('t') or int(time.time()))
    data = body.get('data') or ''
    ctx = body.get('ctx') or {}
    input_str = body.get('input') or build_input(ctx, appkey, t, api, version, data)

    # 首选真机 App 自己的 buildParams：复用已初始化 MtopRequest/Mtop 上下文，
    # 由 App 现场生成 x-sign/x-mini-wua/x-sgext/x-umt，保真度最高。
    result = rpc_json('sign_by_mtop', json.dumps({
        'api': api, 'version': version, 'data': data, 'appKey': appkey
    }, ensure_ascii=False))
    if result and not result.get('error') and any(k.startswith('x-') for k in result):
        return result

    # 次选真机 InnerSignImpl.r —— 与 App 搜索请求走同一个入口。
    if ctx:
        params = {
            'utdid': ctx.get('utdid', ''), 'uid': ctx.get('uid', ''),
            'reqbiz-ext': '', 'data': data, 't': t, 'api': api, 'v': version,
            'sid': ctx.get('sid', ''), 'ttid': ctx.get('ttid', ''),
            'deviceId': ctx.get('deviceId', ''),
            'lat': ctx.get('lat', ''), 'lng': ctx.get('lng', ''),
            'extdata': ctx.get('extdata', 'openappkey=DEFAULT_AUTH'),
            'x-features': str(ctx.get('xFeatures', ctx.get('x-features', '27'))),
        }
        payload = {'api': api, 'version': version, 'params': params,
                   'extend': body.get('extend') or {}, 'requestId': ''}
        result = rpc_json('sign_by_inner', json.dumps(payload, ensure_ascii=False))
        if result and not result.get('error'):
            return result

    # 兜底：直接用真机 getSecurityFactors 签 INPUT
    payload = {'input': input_str, 'appKey': appkey, 'api': api}
    return rpc_json('sign_request', json.dumps(payload, ensure_ascii=False))


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _send(self, obj, code=200):
        raw = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=UTF-8')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        length = int(self.headers.get('Content-Length', 0))
        try:
            return json.loads(self.rfile.read(length).decode('utf-8', 'ignore') or '{}')
        except Exception:
            return {}

    def do_GET(self):
        try:
            if self.path.startswith('/health'):
                status = rpc_json('status')
                self._send({'ok': not bool(_state['error']), 'pid': _state['pid'],
                            'status': status, 'error': _state['error']})
            elif self.path.startswith('/device'):
                self._send(rpc_json('device_info'))
            elif self.path.startswith('/capture'):
                self._send(rpc_json('last_capture'))
            elif self.path.startswith('/debug/'):
                self._send(rpc_json(self.path[len('/debug/'):].split('?')[0]))
            else:
                self._send({'error': 'not found'}, 404)
        except Exception as e:
            self._send({'error': str(e)}, 500)

    def do_POST(self):
        body = self._body()
        try:
            if self.path.startswith('/api/sign/mtop'):
                result = rpc_json('sign_by_mtop', json.dumps(body, ensure_ascii=False))
            elif self.path.startswith('/api/sign/native'):
                result = rpc_json('native_sign', json.dumps(body, ensure_ascii=False))
            elif self.path.startswith('/api/sign/jnic'):
                result = rpc_json('invoke_jnic', json.dumps(body, ensure_ascii=False))
            elif self.path.startswith('/api/sign/sdk'):
                result = rpc_json('sign_sdk', json.dumps(body, ensure_ascii=False))
            elif self.path.startswith('/api/sign/exact'):
                result = rpc_json('sign_exact', json.dumps(body, ensure_ascii=False))
            elif self.path.startswith('/api/sign/legacy'):
                result = rpc_json('sign_legacy', json.dumps({
                    'input': body.get('input', ''), 'appKey': body.get('appKey', '21646297')
                }))
            elif self.path.startswith('/api/search/native'):
                # 免登录原生搜索：App 原生 MtopBuilder 栈发请求，游客态。
                # body: {api, version, data, ttid, method:'POST'|'GET', headers:{}}
                result = rpc_json('native_search', json.dumps(body, ensure_ascii=False))
                log('native search api=%s -> %s' % (
                    body.get('api'), result.get('retCode') or result.get('error')))
                # 注意：不要在 RPC 调用中 disconnect——会与 rpc() 的 session 生命周期
                # 竞争，导致 ThreadingHTTPServer 的响应线程异常退出。session 复用即可。
            elif self.path.startswith('/api/sign'):
                result = sign_payload(body)
            else:
                self._send({'error': 'not found'}, 404)
                return
            if result.get('error'):
                self._send(result, 500)
                return
            result['_rpc_backend'] = 'frida-real-device'
            log('sign api=%s -> %s' % (body.get('api'), ','.join(
                k for k in result if k.startswith('x-'))))
            self._send(result)
        except Exception as e:
            self._send({'error': str(e)}, 500)

    def log_message(self, *args):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=9091)
    ap.add_argument('--package', default=DEFAULT_PACKAGE)
    args = ap.parse_args()
    _state['package'] = args.package

    if not os.path.exists(BUNDLE):
        raise SystemExit('缺少 %s，请先运行 tools/frida/build_rpc_bundle.py' % BUNDLE)

    # 启动即连接，失败时打印原因但不退出，HTTP 侧会按需重连
    try:
        connect(args.package)
    except Exception as e:
        log('初始连接失败: %s（会在请求时重试）' % e)

    log('HTTP 签名服务: http://%s:%d/api/sign' % (args.host, args.port))
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == '__main__':
    sys.exit(main())
