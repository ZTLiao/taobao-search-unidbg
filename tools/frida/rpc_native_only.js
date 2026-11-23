/**
 * 精简版 RPC：只提供 nativeSearch（免登录原生栈搜索），不安装任何诊断 hook。
 *
 * 背景：完整 rpc_sign.js 会在 tb/n9f.r / InnerProtocolParamBuilderImpl.buildParams
 * 等高频方法上安装 hook 并把 Java 参数对象引用保存到全局（C.lastRArgs/C.requestCtx），
 * 这些 JNI 局部引用跨线程/跨调用帧使用会导致 "invalid JNI transition frame reference"
 * SIGABRT（尤其在 frida-gadget 进程内模式）。nativeSearch 本身走 MtopBuilder.syncRequest()，
 * 由 App 原生栈自己签名，完全不需要这些 hook。
 *
 * 与 rpc_sign.js 的 nativeSearch 逻辑一致（Mtop 实例打分选择 + 显式 MtopRequest 重载），
 * 只是移除了所有 hook/诊断副作用。
 */

rpc.exports = {
  nativeSearch: function (payloadJson) {
    var out = {error: null, step: 'start'};
    var payload = {};
    try { payload = JSON.parse(payloadJson || '{}'); } catch (e) {
      return JSON.stringify({error: 'bad payload: ' + e});
    }
    Java.perform(function () {
      try {
        // 1) 选淘宝主进程的 Mtop 实例（按 ID/ttid/utdid/来源打分，排除 Eleme/Koubei/Xianyu）
        var Mtop = Java.use('mtopsdk.mtop.intf.Mtop');
        var mtop = null, iid = null, bestScore = -9999, bestSource = null;
        var candidates = [], seen = {};
        function scoreInstance(inst, source) {
          if (!inst) return;
          var id = '', ttid = '', utdid = '', inited = false;
          try { var v = inst.getInstanceId(); id = v === null ? '' : String(v); } catch (e) {}
          try { var v2 = inst.getTtid(); ttid = v2 === null ? '' : String(v2); } catch (e) {}
          try { var v3 = inst.getUtdid(); utdid = v3 === null ? '' : String(v3); } catch (e) {}
          try { inited = inst.isInited.value === true; } catch (e) {}
          var key = id + '|' + ttid;
          if (seen[key]) return;
          seen[key] = true;
          var low = (id + ' ' + ttid).toLowerCase();
          var score = 0;
          if (low.indexOf('eleme') >= 0 || low.indexOf('koubei') >= 0 || low.indexOf('xianyu') >= 0) score -= 1000;
          if (id === 'MTOP_ID_TAOBAO' || id === 'INNER' || id === 'taobao' || id === '21646297') score += 100;
          if (ttid.indexOf('taobao_android') >= 0) score += 60;
          if (ttid.indexOf('231200@') === 0) score += 20;
          if (utdid.length >= 16) score += 20;
          if (inited) score += 10;
          if (source === 'live-context') score += 40;
          candidates.push({id: id, ttid: ttid.substring(0, 60), utdidLen: utdid.length,
                           inited: inited, source: source, score: score});
          if (score > bestScore) { bestScore = score; mtop = inst; iid = id; bestSource = source; }
        }
        try {
          Java.choose('tb/w4j', {
            onMatch: function (inst) {
              try { var o = inst.o.value; if (o !== null) scoreInstance(o.mtopInstance.value, 'live-context'); } catch (e) {}
            }, onComplete: function () {}
          });
        } catch (e) {}
        try {
          Java.choose('mtopsdk.mtop.intf.Mtop', {
            onMatch: function (inst) { scoreInstance(inst, 'heap'); }, onComplete: function () {}
          });
        } catch (e) {}
        var ids = ['MTOP_ID_TAOBAO', 'INNER', 'taobao', '21646297', ''];
        for (var i = 0; i < ids.length; i++) {
          try { scoreInstance(Mtop.getInstance(ids[i]), 'getInstance'); } catch (e) {}
        }
        if (!mtop || bestScore < 0) {
          out.error = 'no usable Taobao Mtop instance'; out.instanceCandidates = candidates; return;
        }
        out.instanceId = iid; out.instanceSource = bestSource; out.instanceScore = bestScore;
        out.instanceCandidates = candidates;

        // 2) 构造 MtopRequest
        out.step = 'MtopRequest';
        var MtopRequest = Java.use('mtopsdk.mtop.domain.MtopRequest');
        var mreq = MtopRequest.$new();
        mreq.setApiName(payload.api);
        mreq.setVersion(payload.version || '1.0');
        mreq.setData(payload.data);
        try { mreq.setNeedSession(false); } catch (e) {}
        out.reqApi = String(mreq.getApiName());

        // 3) headers
        out.step = 'headers';
        var HashMap = Java.use('java.util.HashMap');
        var hdr = HashMap.$new();
        var H = payload.headers || {};
        Object.keys(H).forEach(function (k) { hdr.put(k, String(H[k])); });

        // 4) MtopBuilder：显式 MtopRequest 重载 + syncRequest
        out.step = 'builder';
        var MB = Java.use('mtopsdk.mtop.intf.MtopBuilder');
        var ctor = MB.$new.overload('mtopsdk.mtop.intf.Mtop',
                                    'mtopsdk.mtop.domain.MtopRequest', 'java.lang.String');
        var ttid = payload.ttid || '231200@taobao_android_10.69.10';
        var builder = ctor.call(MB, mtop, mreq, ttid);
        builder.headers(hdr);
        if (payload.method === 'POST') {
          var MethodEnum = Java.use('mtopsdk.mtop.domain.MethodEnum');
          builder.reqMethod(MethodEnum.POST.value);
          try { builder.allowSwitchToPOST(true); } catch (e) {}
        }
        builder.ttid(ttid);

        out.step = 'syncRequest';
        var resp = builder.syncRequest();
        out.step = 'done';
        if (resp === null) { out.error = 'null response'; return; }
        try { out.retCode = String(resp.getRetCode()); } catch (e) {}
        try { out.retMsg = String(resp.getRetMsg()); } catch (e) {}
        try { var rets = resp.getRet(); out.ret = rets ? String(rets.toString()) : null; } catch (e) {}
        try { var jo = resp.getDataJsonObject(); out.data = jo ? String(jo.toString()) : null; } catch (e) { out.dataErr = String(e); }
        try { out.raw = String(resp.toString()).substring(0, 800); } catch (e) {}
      } catch (e) { out.error = String(e); out.step = out.step || 'ex'; }
    });
    return JSON.stringify(out);
  },

  ping: function () { return 'pong'; }
};
