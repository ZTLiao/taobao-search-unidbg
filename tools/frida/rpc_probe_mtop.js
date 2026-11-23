/**
 * 纯主动调用诊断（无 implementation hook，gadget 安全）：
 * 枚举所有 Mtop 实例 + tb/w4j 存活上下文 + MtopConfig 字段，找出 UI 搜索真正用的签名上下文。
 */
function ss(v) { if (v === null || v === undefined) return ''; try { return String(v); } catch (e) { return ''; } }

rpc.exports = {
  probe: function () {
    var res = { mtops: [], w4j: [], configs: [] };
    Java.perform(function () {
      // 1) 所有 Mtop 实例
      try {
        Java.choose('mtopsdk.mtop.intf.Mtop', {
          onMatch: function (inst) {
            var o = { id: '', ttid: '', utdid: '', appKey: '', inited: '', cfg: {} };
            try { o.id = ss(inst.getInstanceId()); } catch (e) {}
            try { o.ttid = ss(inst.getTtid()); } catch (e) {}
            try { o.utdid = ss(inst.getUtdid()); } catch (e) {}
            try { o.inited = ss(inst.isInited.value); } catch (e) {}
            try {
              var cfg = inst.getMtopConfig ? inst.getMtopConfig() : null;
              if (cfg) {
                ['appKey','ttid','utdid','deviceId','wuaAuthCode','authCode'].forEach(function (k) {
                  try { o.cfg[k] = ss(cfg[k].value !== undefined ? cfg[k].value : cfg[k]); } catch (e) { try { o.cfg[k] = ss(cfg[k]); } catch (e2) {} }
                });
              }
            } catch (e) { o.cfgErr = String(e); }
            if (res.mtops.length < 20) res.mtops.push(o);
          }, onComplete: function () {}
        });
      } catch (e) { res.mtopsErr = String(e); }

      // 2) 存活请求上下文 tb/w4j：枚举字段
      try {
        Java.choose('tb/w4j', {
          onMatch: function (w) {
            if (res.w4j.length >= 3) return 'stop';
            var o = {};
            var fields = ['b','o','i','m','g','h'];
            fields.forEach(function (f) {
              try {
                var v = w[f].value;
                o[f] = v === null ? 'null' : ss(v.getClass().getName());
                if (f === 'b' && v !== null) {
                  // MtopRequest
                  o.b_api = ss(v.getApiName ? v.getApiName() : '');
                  o.b_data = ss(v.getData ? v.getData() : '').substring(0, 200);
                }
              } catch (e) { o[f] = 'ERR'; }
            });
            try {
              var mv = w.m.value;
              if (mv) { o.mKeys = ss(mv.keySet ? mv.keySet().toString() : '').substring(0, 500); }
            } catch (e) {}
            res.w4j.push(o);
          }, onComplete: function () {}
        });
      } catch (e) { res.w4jErr = String(e); }
    });
    return JSON.stringify(res);
  }
};
