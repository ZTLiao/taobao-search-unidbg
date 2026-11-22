#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
终极实验：用真机自身的 MtopBuilder 原生栈发起图搜请求（游客态）。
请求 100% 真机形态（anetwork + 自动签名），不经过我们手工构造 HTTP。
流程：
  1) attach -> 反射诊断 MtopListener 接口方法
  2) registerClass 实现 listener，onResponse 存 MtopResponse
  3) 拿真机 Mtop 实例，new MtopBuilder(mtop, req, ttid).headers(...).asyncRequest()
  4) hook listener 回调拿响应 data/ret
"""
import argparse, base64, json, os, time, subprocess
import frida

ADB = "/Users/liaozetao/.local/android/sdk/platform-tools/adb"
SERIAL = os.environ.get("DEVICE", "cb76b262")
BUNDLE = os.path.join(os.path.dirname(__file__), "frida", "rpc_sign_bundle.js")
API = "mtop.relationrecommend.PailitaoRecommend.recommend"
TEXT_API = "mtop.relationrecommend.MtopRecommend.recommend"
APPKEY = "21646297"

NATIVE_JS = r"""
var __LAST_RESP = null;
var __KNOWN = {};
rpc.exports.diagListener = function () {
  var out = {};
  Java.perform(function () {
    try {
      var ctxStates = [];
      Java.choose('tb/w4j', {
        onMatch: function (inst) {
          var state = {};
          try { state.a = (inst.a.value === null) ? 'null' : String(inst.a.value.getClass().getName()); } catch(e){ state.a='ERR:'+e; }
          try { state.api = inst.b.value ? String(inst.b.value.getApiName()) : 'null'; } catch(e){ state.api='ERR'; }
          try { state.c = (inst.c.value === null) ? 'null' : 'HAS_RESP'; } catch(e){ state.c='ERR'; }
          ctxStates.push(state);
        },
        onComplete: function () {}
      });
      out.contexts = ctxStates;
    } catch (e) { out.error = String(e); }
  });
  return JSON.stringify(out);
};

rpc.exports.nativeRequest = function (reqJson) {
  var out = {error: null, step: 'start'};
  __LAST_RESP = null;
  Java.perform(function () {
    try {
      var req = JSON.parse(reqJson);
      out.step = 'get mtop';
      var Mtop = Java.use('mtopsdk.mtop.intf.Mtop');
      var mtop = null, iid = null;
      // 优先从存活 context 拿 instanceId -> Mtop.getInstance()
      Java.choose('tb/w4j', {
        onMatch: function (inst) {
          if (mtop) return;
          // 从 w4j.o (MtopBuilder) 读 public mtopInstance
          try {
            var o = inst.o.value;
            if (o !== null) {
              var mi = o.mtopInstance.value;
              if (mi !== null) {
                mtop = mi;
                try { iid = String(mi.getInstanceId()); } catch(e){}
                return 'stop';
              }
            }
          } catch(e){}
          // 兜底：从 w4j.a 直接读
          try {
            var a = inst.a.value;
            if (a !== null) { mtop = a; return 'stop'; }
          } catch(e){}
        },
        onComplete: function () {}
      });
      if (!mtop) {
        var candidates = ['', 'taobao', '21646297'];
        for (var ci=0; ci<candidates.length; ci++) {
          try { mtop = Mtop.getInstance(candidates[ci]); if (mtop) { iid=candidates[ci]; break; } } catch(e){}
        }
      }
      if (!mtop) { out.error = 'no Mtop instance'; return; }
      out.mtopClass = String(mtop.getClass().getName());
      out.instanceId = iid;

      out.step = 'build MtopRequest (reuse live)';
      // 复用真机 context 里现成的合法 MtopRequest，只改字段
      var mreq = null, liveO = null;
      Java.choose('tb/w4j', {
        onMatch: function (inst) {
          if (mreq) return;
          try {
            var b = inst.b.value;
            if (b !== null && b.getApiName && b.getApiName()) { mreq = b; liveO = inst.o.value; return 'stop'; }
          } catch(e){}
        },
        onComplete: function () {}
      });
      if (!mreq) { out.error = 'no live MtopRequest to reuse'; return; }
      out.reusedApi = String(mreq.getApiName());
      mreq.setApiName(req.api);
      mreq.setVersion('1.0');
      mreq.setData(req.data);
      try { mreq.setNeedSession(false); } catch (e) {}
      out.newApi = String(mreq.getApiName());

      out.step = 'listener';
      var DefaultMtopListener = Java.use('mtopsdk.mtop.common.DefaultMtopListener');
      var listener = DefaultMtopListener.$new();

      out.step = 'headers';
      var HashMap = Java.use('java.util.HashMap');
      var hdr = HashMap.$new();
      var H = req.headers || {};
      Object.keys(H).forEach(function (k) { hdr.put(k, H[k]); });

      out.step = 'snapshot existing w4j';
      __KNOWN = {};
      Java.choose('tb/w4j', { onMatch: function (inst) { try { __KNOWN[String(inst.hashCode())] = true; } catch(e){} }, onComplete: function () {} });
      out.step = 'asyncRequest';
      var MB = Java.use('mtopsdk.mtop.intf.MtopBuilder');
      // 关键：显式 overload 到 MtopRequest 构造，避免匹配 Object 重载被
      // inputDoToMtopRequest 错误转换（apiName=null -> INIT_ERROR）
      var ctor = MB.$new.overload(
        'mtopsdk.mtop.intf.Mtop',
        'mtopsdk.mtop.domain.MtopRequest',
        'java.lang.String');
      var builder = ctor.call(MB, mtop, mreq, req.ttid || '231200@taobao_android_10.69.10');
      builder.headers(hdr);
      builder.asyncRequest();
      out.step = 'requested';
    } catch (e) { out.error = String(e); }
  });
  return JSON.stringify(out);
};


rpc.exports.dumpAll = function () {
  var arr = [];
  Java.perform(function () {
    Java.choose('tb/w4j', {
      onMatch: function (inst) {
        try {
          var o = {hash: String(inst.hashCode())};
          try { o.api = inst.b.value ? String(inst.b.value.getApiName()) : 'null'; } catch(e){ o.api='ERR'; }
          try {
            var c = inst.c.value;
            if (c !== null) {
              try { o.ret = c.getRet(); } catch(e){ o.retErr=String(e); }
              try { var jo = c.getDataJsonObject(); o.data = jo ? String(jo.toString()).substring(0,300) : 'NULLJO'; } catch(e){ o.dataErr=String(e); }
              try { o.full = String(c.toString()).substring(0,200); } catch(e){}
            } else { o.c = 'null'; }
          } catch(e){ o.cErr = String(e); }
          arr.push(o);
        } catch(e){}
      },
      onComplete: function () {}
    });
  });
  return JSON.stringify(arr);
};

rpc.exports.getResponse = function () {
  var out = {pending: true, knownCount: Object.keys(__KNOWN).length};
  Java.perform(function () {
    Java.choose('tb/w4j', {
      onMatch: function (inst) {
        if (!out.pending) return;
        try {
          var h = String(inst.hashCode());
          if (__KNOWN[h]) return;  // 跳过请求前已存在的
          var c = inst.c.value;
          if (c === null) return;
          var o = {hash: h, ret: null, data: null};
          try { o.full = String(c.toString()); } catch(e){ return; }
          // 只认本次目标 api 的真实响应（排除 UNKNOWN_INIT_ERROR 和 getTimestamp/homepage）
          if (o.full.indexOf('PailitaoRecommend') < 0) return;
          if (o.full.indexOf('ANDROID_SYS_MTOPCONTEXT_INIT_ERROR') >= 0) return;
          try { o.ret = c.getRet(); } catch(e){}
          try { var jo = c.getDataJsonObject(); if (jo !== null) o.data = String(jo.toString()); } catch(e){ o.dataErr = String(e); }
          out = o; out.pending = false;
          return 'stop';
        } catch(e){}
      },
      onComplete: function () {}
    });
  });
  return JSON.stringify(out);
};
"""


def adb(*a):
    try:
        return subprocess.check_output([ADB, "-s", SERIAL] + list(a),
                                       stderr=subprocess.STDOUT).decode("utf-8", "ignore").strip()
    except Exception:
        return ""


def build_data(args):
    if args.text:
        return json.dumps({"requestAlias": "wsearch", "isEnterSrpSearch": "true",
                           "appId": "66", "q": args.q, "n": "20", "page": "1"},
                          ensure_ascii=False, separators=(",", ":"))
    p = {"region": "full", "full_region_size": "full", "biz_type": "pai",
         "subSearchType": "imageText_v3", "m": "api4etao", "n": "60",
         "appId": "32969", "_sid_": "69148", "scene": "multiObject",
         "page": 1, "from": "", "pssource": "sy",
         "extraParams": "use_multi_cat:1;use_pid_summary:1;cat_deleted:1;use_pid_tag:1;extend_count:3"}
    if os.path.exists(args.image):
        with open(args.image, "rb") as f:
            p["strimg"] = base64.b64encode(f.read()).decode("ascii")
    p["q"] = args.q
    inner = json.dumps(p, ensure_ascii=False, separators=(",", ":"))
    return json.dumps({"params": inner, "appId": "32969"}, ensure_ascii=False, separators=(",", ":"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default="/tmp/tb_img/iphone18.jpg")
    ap.add_argument("--q", default="iphone18")
    ap.add_argument("--text", action="store_true")
    args = ap.parse_args()

    pid = adb("shell", "pidof", "com.taobao.taobao")
    pid = pid.split()[0] if pid else ""
    if not pid:
        print("[!] 淘宝未运行"); return
    print("[*] 淘宝 PID:", pid)

    with open(BUNDLE, encoding="utf-8") as f:
        source = f.read()
    sess = None
    try:
        dev = frida.get_device(SERIAL, timeout=10)
        sess = dev.attach(int(pid))
        script = sess.create_script(source + "\n" + NATIVE_JS)
        script.on("message", lambda m, d: None)
        script.load()
        time.sleep(2)

        diag = script.exports_sync.diag_listener()
        print("[*] MtopListener 诊断:", json.dumps(json.loads(diag), ensure_ascii=False)[:1200])

        data = build_data(args)
        api = TEXT_API if args.text else API
        payload = {"api": api, "version": "1.0", "appKey": APPKEY, "data": data,
                   "ctx": {"utdid": "awJ3hY/Mq3EDAMWt0Bs6MAqV", "ttid": "231200@taobao_android_10.69.10"}}
        raw = script.exports_sync.sign_by_mtop(json.dumps(payload, ensure_ascii=False))
        s = json.loads(raw) if isinstance(raw, str) else raw
        if s.get("error"):
            print("[!] signByMtop 失败:", s.get("error")); return
        print("[*] 真机签名 OK")

        headers = {"x-mini-wua": s.get("x-mini-wua", ""), "x-sgext": s.get("x-sgext", ""),
                   "x-gst": s.get("x-gst", ""), "x-utdid": s.get("utdid", ""),
                   "x-devid": s.get("deviceId", "")}
        reqj = json.dumps({"api": api, "data": data, "ttid": s.get("ttid", ""),
                           "headers": headers}, ensure_ascii=False)
        r = script.exports_sync.native_request(reqj)
        print("[*] nativeRequest:", json.dumps(json.loads(r), ensure_ascii=False)[:600])
        time.sleep(4)
        print("[*] 所有 w4j 状态:")
        try:
            print(json.dumps(json.loads(script.exports_sync.dump_all()), ensure_ascii=False, indent=1)[:5000])
        except Exception as e:
            print("  dumpAll err:", e)

        for i in range(40):
            time.sleep(1)
            resp = json.loads(script.exports_sync.get_response())
            if not resp.get("pending"):
                print("\n" + "=" * 70)
                print("真机原生 Mtop 响应:", json.dumps(resp, ensure_ascii=False)[:6000])
                print("=" * 70)
                return
        print("[!] 40s 内无响应回调")
    except Exception as e:
        print("[!] 异常:", str(e)[:300])
    finally:
        try:
            if sess: sess.detach()
        except Exception:
            pass


if __name__ == "__main__":
    main()
