/**
 * sg_fopen_redirect.js —— 破解 SG 1927 的精准 native hook（由 build_rpc_bundle 拼 bridge）
 *
 * 决定性证据（sg_read_fulltrace 实测）：
 *   SG 读 base.apk 的主路径是 fopen(path,"rb")，caller 栈顶直接是 libsgmainso；
 *   其底层 open 的 caller 栈顶是 libc.so，所以旧版只 hook open 家族 + 要求栈顶
 *   libsgmainso 的判定会漏掉 fopen 路径 —— 这正是 native 重定向只降到 21 的原因。
 *
 * 本 hook：
 *   路 A：hook fopen —— SG 打开 base.apk 时把路径替换为官方 APK（主路径）
 *   路 B：hook open/openat 家族 —— 放宽 caller 判定（任一帧含 sgmain 即可），兜底
 * 只做 native 路径参数替换，不碰任何 Java 对象字段，避免 JNI 跨帧 SIGABRT。
 */
(function () {
  var PKG = 'com.taobao.taobao';
  var OFFICIAL_APK = '/data/local/tmp/official_base.apk';
  var STATUS = '/data/local/tmp/sg_fopen_status.txt';
  var stat = {fopenRedirects: 0, openRedirects: 0, fopenSeen: [], errors: []};
  globalThis.__sgFopen = stat;

  function log(s) {
    console.log('[SG-OPEN] ' + s);
    try { var f = new File(STATUS, 'a'); f.write(s + '\n'); f.close(); } catch (e) {}
  }
  function callerHasSG(ctx) {
    try {
      var bt = Thread.backtrace(ctx, Backtracer.FUZZY);
      for (var i = 0; i < bt.length && i < 16; i++) {
        var m = Process.getModuleByAddress(bt[i]);
        if (m && m.name.toLowerCase().indexOf('sgmain') >= 0) return true;
      }
    } catch (e) {}
    return false;
  }

  // 路 A：fopen 重定向（主路径）——必须从 libc.so 取导出，Module.getExportByName(null,...) 在本环境返回 null
  var _libc = Process.getModuleByName('libc.so');
  function libcExp(n) { try { return _libc.getExportByName(n); } catch (e) { return null; } }
  ['fopen', 'fopen64'].forEach(function (fn) {
    var addr = libcExp(fn);
    if (!addr) { log('fopen export not found: ' + fn); return; }
    try {
      Interceptor.attach(addr, {
        onEnter: function (args) {
          try {
            var p = args[0].readCString() || '';
            if (p.indexOf('base.apk') >= 0 && p.indexOf(PKG) >= 0 && callerHasSG(this.context)) {
              stat.fopenRedirects++;
              if (stat.fopenRedirects <= 8) log('FOPEN redirect ' + fn + ' ' + p + ' -> ' + OFFICIAL_APK);
              this._newp = Memory.allocUtf8String(OFFICIAL_APK);
              args[0] = this._newp;
            }
          } catch (e) {}
        }
      });
      log('hooked ' + fn + ' @' + addr);
    } catch (e) { stat.errors.push(fn + ': ' + e); }
  });

  // 路 B：open 家族兜底（放宽 caller：任一帧含 sgmain，不限 flags 栈顶）
  var libc = Process.getModuleByName('libc.so');
  function exp(n) { try { return libc.getExportByName(n); } catch (e) { return null; } }
  [['open', 0], ['open64', 0], ['__open_2', 0],
   ['openat', 1], ['openat64', 1], ['__openat_2', 1]].forEach(function (spec) {
    var fn = spec[0], pi = spec[1];
    var addr = exp(fn); if (!addr) return;
    try {
      Interceptor.attach(addr, {
        onEnter: function (args) {
          try {
            var p = args[pi].readCString() || '';
            if (p.indexOf('base.apk') >= 0 && p.indexOf(PKG) >= 0 && callerHasSG(this.context)) {
              stat.openRedirects++;
              if (stat.openRedirects <= 8) log('OPEN redirect ' + fn + ' ' + p + ' -> ' + OFFICIAL_APK);
              this._newp = Memory.allocUtf8String(OFFICIAL_APK);
              args[pi] = this._newp;
            }
          } catch (e) {}
        }
      });
      log('hooked ' + fn + ' @' + addr);
    } catch (e) { stat.errors.push(fn + ': ' + e); }
  });

  try {
    rpc.exports = {
      init: function () { return Promise.resolve(); },
      status: function () { return JSON.stringify(stat); }
    };
  } catch (e) {}
})();
