#!/usr/bin/env python3
"""
模拟 unidbg-server 的 HTTP 签名服务（用于验证 rpc 签名后端通路）。

真实部署时把它换成你自建的 unidbg-server / 真机 frida-rpc 签名接口即可，工程侧
只需配置 sign.rpc.url，无需改代码：
  POST /api/sign  {"api","version","appKey","t","data","token","cookie"}
  -> {"sign":"...", "x-sign":"...", "x-sgext":"...", "x-mini-wua":"..."}

本示例用 H5 标准算法生成 sign，使本地 mock 网关能校验通过，从而证明
「请求编排 -> 外部签名服务 -> 网关」整条链路贯通。

启动: python3 tools/mock_sign_rpc.py 8098
"""
import hashlib
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8098


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8", "ignore") or "{}")
        except Exception:
            body = {}
        tk = body.get("token") or ""
        t = str(body.get("t", ""))
        ak = str(body.get("appKey", ""))
        data = body.get("data") or ""
        sign = hashlib.md5(f"{tk}&{t}&{ak}&{data}".encode("utf-8")).hexdigest()

        resp = {
            "sign": sign,
            "x-sign": sign,
            "x-sgext": "mock-sgext",
            "x-mini-wua": "mock-wua",
            "_source": "mock-unidbg-server",
        }
        raw = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=UTF-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
        print(f"[sign-rpc] api={body.get('api')} token={'present' if tk else 'none'} "
              f"-> sign={sign[:8]}..", flush=True)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"mock sign RPC (stand-in for unidbg-server) on "
          f"http://127.0.0.1:{PORT}/api/sign", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
