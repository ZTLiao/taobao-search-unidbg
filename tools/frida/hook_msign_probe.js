/*
 * 探测真机 App 搜索请求是否产生 m-pv / m-sign / m-appkey / m-t 头族。
 * hook java.util.HashMap.put / LinkedHashMap.put / ArrayMap.put，过滤目标 key。
 */
'use strict';

var KEYS = ['m-pv', 'm-sign', 'm-appkey', 'm-t', 'x-pv', 'pv', 'x-sign'];
var C = { hits: [], count: 0 };

function watchPut(Cls, label) {
  try {
    var P = Java.use(Cls);
    var puts = P.put.overloads;
    puts.forEach(function (ov) {
      ov.implementation = function (k, v) {
        try {
          var ks = String(k);
          if (KEYS.indexOf(ks) >= 0 && C.hits.length < 60) {
            C.hits.push(label + ' ' + ks + '=' + String(v).substring(0, 150));
            C.count++;
          }
        } catch (e) {}
        return ov.apply(this, arguments);
      };
    });
    C[label] = 'ok';
  } catch (e) { C[label] = 'ERR ' + e; }
}

Java.perform(function () {
  watchPut('java.util.HashMap', 'HashMap');
  watchPut('java.util.LinkedHashMap', 'LinkedHashMap');
  try { watchPut('android.util.ArrayMap', 'ArrayMap'); } catch (e) {}
  console.log('[msign-probe] ready');
});

rpc.exports = {
  hits: function () { return JSON.stringify(C); },
  clear: function () { C.hits = []; C.count = 0; return 'ok'; }
};
