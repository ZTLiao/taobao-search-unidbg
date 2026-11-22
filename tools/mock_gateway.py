#!/usr/bin/env python3
"""
本地 MTOP mock 网关：完整模拟 H5 标准 token 握手 + sign 校验。

与真实 h5api.m.taobao.com 一致的握手流程：
  1) 客户端首次请求无 _m_h5_tk Cookie
     -> 返回 FAIL_SYS_TOKEN_EXPIRED，Set-Cookie 下发 _m_h5_tk=<token>_<ts>、_m_h5_tk_enc
  2) 客户端带 Cookie，且 sign == md5(token&t&appKey&data)
     -> 返回 SUCCESS + 商品列表
  3) sign 不匹配 -> 返回 FAIL_SYS_TOKEN_EXPIRED 要求刷新重算

启动: python3 tools/mock_gateway.py 8099
把 mtop.gateway 指向 http://127.0.0.1:8099/ 即可端到端验证握手闭环，
无需连生产网关。GET / 可查看握手统计。
"""
import hashlib
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
TOKEN = "mockh5tk" + str(int(time.time()))
ISSUED = set()
COUNTER = {"req": 0, "challenge": 0, "success": 0, "sign_reject": 0}


def token_from_cookie(cookie_header):
    """从 Cookie 头取 _m_h5_tk 的 token 部分（最后一个下划线前）。"""
    if not cookie_header:
        return None
    for part in cookie_header.split(";"):
        p = part.strip()
        if p.startswith("_m_h5_tk="):
            raw = p[len("_m_h5_tk="):]
            idx = raw.rfind("_")
            return raw[:idx] if idx > 0 else raw
    return None


def build_data(api):
    if "PailitaoRecommend" in api:
        return {"resultList": [
            {"itemId": "1001", "title": "图片识别结果-同款连衣裙", "price": "129.00",
             "picUrl": "https://img.alicdn.com/mock/1.jpg"},
            {"itemId": "1002", "title": "图片识别结果-相似款", "price": "89.00",
             "picUrl": "https://img.alicdn.com/mock/2.jpg"}],
            "sessionId": "mock-plt-session"}
    if "suggest" in api:
        return {"suggestList": ["连衣裙", "连衣裙女", "连衣裙夏季"]}
    return {"resultList": [
        {"itemId": "2001", "title": "mock 商品 A", "price": "99.00",
         "picUrl": "https://img.alicdn.com/mock/a.jpg"},
        {"itemId": "2002", "title": "mock 商品 B", "price": "199.00",
         "picUrl": "https://img.alicdn.com/mock/b.jpg"}]}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        COUNTER["req"] += 1
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length).decode("utf-8", "ignore") if length else ""
        parsed = urlparse(self.path)
        q = parse_qs(parsed.query, keep_blank_values=True)
        body_q = parse_qs(raw_body, keep_blank_values=True)
        params = dict(body_q)
        for k, v in q.items():
            params.setdefault(k, v)

        def g(k, d=""):
            v = params.get(k)
            return v[0] if v else d

        parts = [x for x in parsed.path.split("/") if x]
        api = g("api") or g("mtopapi") or (parts[-2] if len(parts) >= 2 else "unknown")
        t = g("t")
        app_key = g("appKey")
        data = g("data")
        sign = g("sign")
        cookie = self.headers.get("Cookie", "")
        token = token_from_cookie(cookie)
        n = COUNTER["req"]

        # 1) 无 token / 未签发 -> 下发 token，要求客户端重算 sign 重试
        if not token or token not in ISSUED:
            COUNTER["challenge"] += 1
            self._challenge(api, "FAIL_SYS_TOKEN_EXPIRED::令牌为空或已过期")
            print(f"[req{n}] {api} no-valid-token -> challenge (Set-Cookie _m_h5_tk)", flush=True)
            return

        # 2) 校验 sign = md5(token&t&appKey&data)
        expect = hashlib.md5(f"{token}&{t}&{app_key}&{data}".encode("utf-8")).hexdigest()
        if sign != expect:
            COUNTER["sign_reject"] += 1
            self._challenge(api, "FAIL_SYS_TOKEN_EXPIRED::签名无效，请刷新令牌")
            print(f"[req{n}] {api} sign mismatch -> challenge "
                  f"(got={sign[:8]}.. expect={expect[:8]}..)", flush=True)
            return

        # 3) 成功
        COUNTER["success"] += 1
        # 图片搜索：解析 data(JSON) 里的 strimg/searchimg，实证图片是否真的上传
        if "PailitaoRecommend" in api:
            try:
                biz = json.loads(data)
                strimg = biz.get("strimg") or ""
                searchimg = biz.get("searchimg") or ""
                if strimg:
                    COUNTER["imageUploads"] = COUNTER.get("imageUploads", 0) + 1
                    print(f"[req{n}] IMAGE UPLOAD strimg.len={len(strimg)} "
                          f"prefix={strimg[:16]} region={biz.get('region')}", flush=True)
                elif searchimg:
                    COUNTER["imageUploads"] = COUNTER.get("imageUploads", 0) + 1
                    print(f"[req{n}] IMAGE URL searchimg={searchimg[:80]}", flush=True)
            except Exception:
                pass
        resp = {"api": api, "v": g("v", "1.0"),
                "ret": ["SUCCESS::调用成功"], "data": build_data(api)}
        self._send(resp)
        print(f"[req{n}] {api} SIGN OK -> SUCCESS (token={token[:12]}...)", flush=True)

    def _challenge(self, api, ret):
        ts = int(time.time() * 1000)
        raw = f"{TOKEN}_{ts}"
        ISSUED.add(TOKEN)
        resp = {"api": api, "v": "1.0", "ret": [ret], "data": {}}
        body = json.dumps(resp, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=UTF-8")
        self.send_header("Set-Cookie", f"_m_h5_tk={raw}; Path=/; HttpOnly")
        self.send_header("Set-Cookie", f"_m_h5_tk_enc=mockenc{ts}; Path=/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send(self, resp):
        body = json.dumps(resp, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        stats = dict(COUNTER)
        stats["issuedTokens"] = len(ISSUED)
        stats["token"] = TOKEN
        body = json.dumps(stats, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"mock MTOP gateway (H5 token handshake) on http://127.0.0.1:{PORT}/", flush=True)
    print(f"pre-issued token: {TOKEN}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
