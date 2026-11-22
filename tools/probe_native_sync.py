#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
免登录搜索 - 真机/模拟器原生 Mtop 栈（同步版）。

核心：Frida 内用 App 自己的 Mtop 实例 + MtopBuilder.syncRequest() 发请求，
请求 100% 走 anetwork 原生协议栈（自动签名 + 原生请求形态），
绕开手工 HTTP form 被 bixi 标记为 wh_ttid=pc 的 web 风控。

关键修复：
  1) MtopBuilder.$new 必须 overload 到 MtopRequest 构造（否则匹配 Object 重载
     -> inputDoToMtopRequest 错误转换 -> apiName=null -> INIT_ERROR）
  2) reqMethod(POST) 避免图片 base64 走 GET 导致 414 参数超长
  3) syncRequest() 直接同步拿 MtopResponse，不轮询 w4j
"""
import argparse, base64, json, os, time, subprocess
import frida

ADB = "/Users/liaozetao/.local/android/sdk/platform-tools/adb"
SERIAL = os.environ.get("DEVICE", "emulator-5554")
BUNDLE = os.path.join(os.path.dirname(__file__), "frida", "rpc_sign_bundle.js")
API = "mtop.relationrecommend.PailitaoRecommend.recommend"
TEXT_API = "mtop.relationrecommend.MtopRecommend.recommend"
APPKEY = "21646297"

NATIVE_JS = r"""
rpc.exports.nativeSync = function (reqJson) {
  var out = {error: null, step: 'start'};
  Java.perform(function () {
    try {
      var req = JSON.parse(reqJson);
      // 1) 拿真机 Mtop 实例（优先存活 context 的 builder.mtopInstance）
      var Mtop = Java.use('mtopsdk.mtop.intf.Mtop');
      var mtop = null, iid = null;
      Java.choose('tb/w4j', {
        onMatch: function (inst) {
          if (mtop) return;
          try {
            var o = inst.o.value;
            if (o !== null) {
              var mi = o.mtopInstance.value;
              if (mi !== null) { mtop = mi; try { iid = String(mi.getInstanceId()); } catch(e){} return 'stop'; }
            }
          } catch(e){}
        }, onComplete: function () {}
      });
      if (!mtop) {
        var cands = ['', 'INNER', 'taobao', '21646297'];
        for (var i=0; i<cands.length; i++) {
          try { mtop = Mtop.getInstance(cands[i]); if (mtop) { iid=cands[i]; break; } } catch(e){}
        }
      }
      if (!mtop) { out.error='no Mtop instance'; return; }
      out.instanceId = iid;

      // 2) 新建合法 MtopRequest，显式字段赋值
      out.step = 'MtopRequest';
      var MtopRequest = Java.use('mtopsdk.mtop.domain.MtopRequest');
      var mreq = MtopRequest.$new();
      mreq.setApiName(req.api);
      mreq.setVersion(req.version || '1.0');
      mreq.setData(req.data);
      try { mreq.setNeedSession(false); } catch(e){}
      out.reqApi = String(mreq.getApiName());

      // 3) 头族
      out.step = 'headers';
      var HashMap = Java.use('java.util.HashMap');
      var hdr = HashMap.$new();
      var H = req.headers || {};
      Object.keys(H).forEach(function(k){ hdr.put(k, String(H[k])); });

      // 4) MtopBuilder：显式 MtopRequest 重载 + POST + syncRequest
      out.step = 'builder';
      var MB = Java.use('mtopsdk.mtop.intf.MtopBuilder');
      var ctor = MB.$new.overload('mtopsdk.mtop.intf.Mtop',
                                  'mtopsdk.mtop.domain.MtopRequest', 'java.lang.String');
      var builder = ctor.call(MB, mtop, mreq, req.ttid);
      builder.headers(hdr);
      if (req.method === 'POST') {
        var MethodEnum = Java.use('mtopsdk.mtop.domain.MethodEnum');
        builder.reqMethod(MethodEnum.POST.value);
        try { builder.allowSwitchToPOST(true); } catch(e){}
      }
      builder.ttid(req.ttid);

      out.step = 'syncRequest';
      var resp = builder.syncRequest();
      out.step = 'done';
      if (resp === null) { out.error='null response'; return; }
      try { out.retCode = String(resp.getRetCode()); } catch(e){}
      try { out.retMsg = String(resp.getRetMsg()); } catch(e){}
      try { var rets = resp.getRet(); out.ret = rets ? String(rets.toString()) : null; } catch(e){}
      try {
        var jo = resp.getDataJsonObject();
        out.data = jo ? String(jo.toString()) : null;
      } catch(e){ out.dataErr = String(e); }
      try { out.raw = String(resp.toString()).substring(0, 500); } catch(e){}
    } catch (e) { out.error = String(e); out.step = out.step || 'ex'; }
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
        inner = json.dumps({"requestAlias": "wsearch", "isEnterSrpSearch": "true",
                            "appId": "66", "q": args.q, "n": "20", "page": "1"},
                           ensure_ascii=False, separators=(",", ":"))
        return inner
    p = {"region": "full", "full_region_size": "full", "biz_type": "pai",
         "subSearchType": "imageText_v3", "m": "api4etao", "n": "60",
         "appId": "32969", "_sid_": "69148", "scene": "multiObject",
         "page": 1, "from": "", "pssource": "sy",
         "extraParams": "use_multi_cat:1;use_pid_summary:1;cat_deleted:1;use_pid_tag:1;extend_count:3"}
    if args.image and os.path.exists(args.image):
        with open(args.image, "rb") as f:
            p["strimg"] = base64.b64encode(f.read()).decode("ascii")
    if args.q:
        p["q"] = args.q
    inner = json.dumps(p, ensure_ascii=False, separators=(",", ":"))
    return json.dumps({"params": inner, "appId": "32969"}, ensure_ascii=False, separators=(",", ":"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default="/tmp/tb_img/iphone18.jpg")
    ap.add_argument("--q", default="iphone18")
    ap.add_argument("--text", action="store_true")
    ap.add_argument("--method", default="POST", choices=["POST", "GET"])
    ap.add_argument("--serial", default=None)
    args = ap.parse_args()

    global SERIAL
    if args.serial:
        SERIAL = args.serial
        globals()["ADB"] = ADB
    # 修正 adb() 闭包里用的 SERIAL
    import builtins
    builtins.__dict__["_TB_SERIAL"] = SERIAL

    pid = adb("shell", "pidof", "com.taobao.taobao")
    pid = pid.split()[0] if pid else ""
    if not pid:
        print("[!] 淘宝未运行"); return
    print("[*] 设备:", SERIAL, "淘宝 PID:", pid)

    with open(BUNDLE, encoding="utf-8") as f:
        source = f.read()
    sess = None
    try:
        dev = frida.get_device(SERIAL, timeout=10)
        sess = dev.attach(int(pid))
        script = sess.create_script(source + "\n" + NATIVE_JS)
        script.on("message", lambda m, d: None)
        script.load()
        time.sleep(1)

        data = build_data(args)
        api = TEXT_API if args.text else API
        ttid = "231200@taobao_android_10.69.10"
        print("[*] api=%s data.len=%d method=%s" % (api, len(data), args.method))

        req = {"api": api, "version": "1.0", "data": data,
               "ttid": ttid, "method": args.method, "headers": {}}
        r = script.exports_sync.native_sync(json.dumps(req, ensure_ascii=False))
        out = json.loads(r) if isinstance(r, str) else r
        print("\n" + "=" * 70)
        print("原生 Mtop 同步响应:")
        print(json.dumps(out, ensure_ascii=False, indent=1)[:12000])
        print("=" * 70)
    except Exception as e:
        print("[!] 异常:", str(e)[:500])
    finally:
        try:
            if sess: sess.detach()
        except Exception:
            pass


if __name__ == "__main__":
    main()
