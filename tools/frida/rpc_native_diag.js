/**
 * 统一诊断脚本：纯主动调用（无任何 implementation hook，gadget 安全）。
 * 同时提供：
 *  - probe()      : 枚举 Mtop 实例/MtopConfig/tb-w4j，找 UI 搜索真正用的签名上下文
 *  - nativeSearch(): 用 App 原生栈发搜索（主动调用 MtopBuilder）
 *  - ping()
 */
function ss(v) { if (v === null || v === undefined) return ''; try { return String(v); } catch (e) { return ''; } }

function probeMtops() {
  var res = { mtops: [], w4j: [] };
  try {
    Java.choose('mtopsdk.mtop.intf.Mtop', {
      onMatch: function (inst) {
        var o = { id: '', ttid: '', utdid: '', inited: '', cfg: {} };
        try { o.id = ss(inst.getInstanceId()); } catch (e) {}
        try { o.ttid = ss(inst.getTtid()); } catch (e) {}
        try { o.utdid = ss(inst.getUtdid()); } catch (e) {}
        try { o.inited = ss(inst.isInited.value); } catch (e) {}
        try {
          var cfg = inst.getMtopConfig ? inst.getMtopConfig() : inst.m.config.value;
          if (cfg) {
            ['appKey','ttid','utdid','deviceId','wuaAuthCode'].forEach(function (k) {
              try {
                var f = cfg.getClass().getDeclaredField(k); f.setAccessible(true);
                o.cfg[k] = ss(f.get(cfg)).substring(0, 80);
              } catch (e) {}
            });
          }
        } catch (e) { o.cfgErr = String(e); }
        if (res.mtops.length < 20) res.mtops.push(o);
      }, onComplete: function () {}
    });
  } catch (e) { res.mtopsErr = String(e); }
  try {
    Java.choose('tb/w4j', {
      onMatch: function (w) {
        if (res.w4j.length >= 3) return 'stop';
        var o = {};
        ['b','o','m'].forEach(function (f) {
          try { var v = w[f].value; o[f] = v === null ? 'null' : ss(v.getClass().getName()); }
          catch (e) { o[f] = 'ERR'; }
        });
        try { var b = w.b.value; if (b) { o.api = ss(b.getApiName()); o.data = ss(b.getData()).substring(0,150); } } catch (e) {}
        res.w4j.push(o);
      }, onComplete: function () {}
    });
  } catch (e) { res.w4jErr = String(e); }
  return res;
}

rpc.exports = {
  ping: function () { return 'pong'; },
  probe: function () {
    var out = {};
    Java.perform(function () { out = probeMtops(); });
    return JSON.stringify(out);
  },
  nativeSearch: function (payloadJson) {
    var out = {error: null, step: 'start'};
    var payload = {};
    try { payload = JSON.parse(payloadJson || '{}'); } catch (e) { return JSON.stringify({error: 'bad payload: ' + e}); }
    Java.perform(function () {
      try {
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
          var key = id + '|' + ttid; if (seen[key]) return; seen[key] = true;
          var low = (id + ' ' + ttid).toLowerCase(); var score = 0;
          if (low.indexOf('eleme') >= 0 || low.indexOf('koubei') >= 0 || low.indexOf('xianyu') >= 0) score -= 1000;
          if (id === 'MTOP_ID_TAOBAO' || id === 'INNER' || id === 'taobao' || id === '21646297') score += 100;
          if (ttid.indexOf('taobao_android') >= 0) score += 60;
          if (ttid.indexOf('231200@') === 0) score += 20;
          if (utdid.length >= 16) score += 20;
          if (inited) score += 10;
          if (source === 'live-context') score += 40;
          candidates.push({id: id, ttid: ttid.substring(0,60), utdidLen: utdid.length, inited: inited, source: source, score: score});
          if (score > bestScore) { bestScore = score; mtop = inst; iid = id; bestSource = source; }
        }
        try { Java.choose('tb/w4j', { onMatch: function (inst) { try { var o = inst.o.value; if (o !== null) scoreInstance(o.mtopInstance.value, 'live-context'); } catch (e) {} }, onComplete: function () {} }); } catch (e) {}
        try { Java.choose('mtopsdk.mtop.intf.Mtop', { onMatch: function (inst) { scoreInstance(inst, 'heap'); }, onComplete: function () {} }); } catch (e) {}
        var ids = ['MTOP_ID_TAOBAO','INNER','taobao','21646297',''];
        for (var i = 0; i < ids.length; i++) { try { scoreInstance(Mtop.getInstance(ids[i]), 'getInstance'); } catch (e) {} }
        out.instanceId = iid; out.instanceScore = bestScore; out.instanceCandidates = candidates;
        if (!mtop || bestScore < 0) { out.error = 'no usable Mtop'; return; }

        // 允许 payload 指定 instanceId 覆盖
        if (payload.instanceId) {
          for (var j = 0; j < candidates.length; j++) {
            if (candidates[j].id === payload.instanceId) {
              try { mtop = Mtop.getInstance(payload.instanceId); iid = payload.instanceId; out.instanceId = iid; } catch (e) {}
            }
          }
        }

        out.step = 'MtopRequest';
        var MtopRequest = Java.use('mtopsdk.mtop.domain.MtopRequest');
        var mreq = MtopRequest.$new();
        mreq.setApiName(payload.api);
        mreq.setVersion(payload.version || '1.0');
        mreq.setData(payload.data);
        try { mreq.setNeedSession(false); } catch (e) {}
        out.reqApi = String(mreq.getApiName());

        out.step = 'builder';
        var HashMap = Java.use('java.util.HashMap');
        var hdr = HashMap.$new();
        var H = payload.headers || {};
        Object.keys(H).forEach(function (k) { hdr.put(k, String(H[k])); });
        var MB = Java.use('mtopsdk.mtop.intf.MtopBuilder');
        var ctor = MB.$new.overload('mtopsdk.mtop.intf.Mtop','mtopsdk.mtop.domain.MtopRequest','java.lang.String');
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
        try { var jo = resp.getDataJsonObject(); out.data = jo ? String(jo.toString()) : null; } catch (e) {}
        try { out.raw = String(resp.toString()).substring(0, 600); } catch (e) {}
      } catch (e) { out.error = String(e); out.step = out.step || 'ex'; }
    });
    return JSON.stringify(out);
  }
};
