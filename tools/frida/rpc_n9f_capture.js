/**
 * 只 hook tb/n9f.r（签名方法），值拷贝抓成功四头，绝不保存 Java 对象引用到全局。
 * 与 buildParams hook 不同，n9f.r hook 在完整 bundle 里已被证明稳定（rCallCount 可增长）。
 */
var C = { heads: null, calls: 0, successes: 0, ready: false, hooks: [], lastApi: '' };

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
      out[k] = safeStr(map.get(keys[i])).substring(0, 4000);
    }
  } catch (e) { out._error = String(e); }
  return out;
}

function install() {
  Java.perform(function () {
    try {
      var N9 = Java.use('tb/n9f');
      N9.r.overloads.forEach(function (ov) {
        ov.implementation = function () {
          C.calls++;
          try { C.lastApi = safeStr(arguments[2]); } catch (e) {}
          var ret = ov.apply(this, arguments);
          try {
            var m = mapToStrings(ret);  // 值拷贝
            var keys = Object.keys(m);
            var hasSign = keys.some(function (k) { return /^(x-mini-wua|x-sgext|x-sign|wua|sign)$/.test(k); });
            if (hasSign) {
              C.successes++;
              C.heads = m;  // 纯 JS 对象，不是 jobject
            }
          } catch (e) {}
          return ret;
        };
      });
      C.hooks.push('n9f.r: ok');
    } catch (e) { C.hooks.push('n9f.r: ' + e); }
    C.ready = true;
    console.log('[n9f-capture] ready ' + C.hooks.join(' | '));
  });
}

rpc.exports = {
  status: function () { return { ready: C.ready, calls: C.calls, successes: C.successes, lastApi: C.lastApi, hooks: C.hooks }; },
  heads: function () { return C.heads || { error: 'no captured heads' }; }
};

install();
