/**
 * 安全的签名捕获脚本：只做值拷贝，绝不保存 Java 对象引用到全局，
 * 避免在 frida-gadget 进程内模式触发 "invalid JNI transition frame reference" SIGABRT。
 *
 * 提供：
 *  - 自动 hook InnerProtocolParamBuilderImpl.buildParams，把每次请求的参数快照
 *    转成纯 JS 对象（字符串值），存到 C.snapshots 数组（只存字符串，不存 jobject）。
 *  - lastSearch() 返回最近一次「搜索类」请求快照。
 *  - status() 返回就绪状态。
 */

var C = { snapshots: [], maxSnapshots: 20, ready: false, hooks: [] };

function safeStr(v) {
  if (v === null || v === undefined) return '';
  try { return String(v); } catch (e) { return ''; }
}

function mapToStrings(map) {
  var out = {};
  try {
    var keys = map.keySet().toArray();
    for (var i = 0; i < keys.length; i++) {
      var k = safeStr(keys[i]);
      var v = map.get(keys[i]);
      out[k] = safeStr(v).substring(0, 4000);
    }
  } catch (e) { out._error = String(e); }
  return out;
}

function installHook() {
  Java.perform(function () {
    try {
      var IPB = Java.use('mtopsdk.mtop.protocol.builder.impl.InnerProtocolParamBuilderImpl');
      IPB.buildParams.overloads.forEach(function (ov) {
        ov.implementation = function () {
          var out = ov.apply(this, arguments);
          try {
            var p = mapToStrings(out);  // 只做值拷贝
            if (C.snapshots.length >= C.maxSnapshots) C.snapshots.shift();
            C.snapshots.push({
              ts: Date.now(),
              params: p,
              api: p['api'] || ''
            });
          } catch (e) {}
          return out;  // 原样返回，不保存任何 Java 对象引用
        };
      });
      C.hooks.push('buildParams: ok');
    } catch (e) { C.hooks.push('buildParams: ' + e); }
    C.ready = true;
    console.log('[capture-safe] ready hooks=' + C.hooks.join(' | '));
  });
}

rpc.exports = {
  status: function () { return { ready: C.ready, count: C.snapshots.length, hooks: C.hooks }; },
  lastSearch: function () {
    for (var i = C.snapshots.length - 1; i >= 0; i--) {
      var s = C.snapshots[i];
      var api = s.api || '';
      if (api.indexOf('recommend') >= 0 || api.indexOf('search') >= 0 || api.indexOf('wsearch') >= 0) {
        return s;
      }
    }
    return C.snapshots.length ? C.snapshots[C.snapshots.length - 1] : {error: 'no snapshots'};
  },
  allApis: function () {
    return C.snapshots.map(function (s) { return s.api; });
  },
  clear: function () { C.snapshots = []; return true; }
};

installHook();
