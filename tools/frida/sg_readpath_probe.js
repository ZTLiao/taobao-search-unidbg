/**
 * sg_readpath_probe.js —— 诊断 SG 到底从哪里读 APK 签名
 *
 * 用途：当 sg_sigspoof hook getPackageInfo 后 1927 仍存在时，判断 SG core
 *       是否绕过 Java 层、直接用 native open() 读 /data/app/.../base.apk 的签名块。
 *
 * Hook 点：
 *   1) libc open/openat —— 看 SG 初始化期是否 open 了 base.apk
 *   2) java.io.FileInputStream / RandomAccessFile 构造 —— 间接读文件
 *   3) getPackageInfo —— 已知路径（dbo）
 *
 * 加载方式（listen 模式即可，重启 App 前 attach 会晚；建议 script-directory）：
 *   adb push sg_readpath_probe_bundle.js /data/local/tmp/frida-scripts/probe.script
 */
(function () {
  var PKG = 'com.taobao.taobao';
  var stat = {opens: [], javaReads: [], pkgHits: 0};
  globalThis.__sgProbe = stat;

  function log(s) { console.log('[SG-PROBE] ' + s); }

  // native open/openat：记录打开 apk / 签名相关文件
  ['open', 'openat'].forEach(function (fn) {
    try {
      var addr = Module.findExportByName('libc.so', fn);
      if (!addr) return;
      Interceptor.attach(addr, {
        onEnter: function (args) {
          try {
            var p = (fn === 'openat' ? args[1] : args[0]).readCString() || '';
            if (p.indexOf('base.apk') >= 0 || p.indexOf('CERT.RSA') >= 0 ||
                p.indexOf('yw_1222') >= 0 || p.indexOf('.apk') >= 0) {
              var rec = fn + ' ' + p;
              if (stat.opens.length < 30) { stat.opens.push(rec); log('OPEN ' + rec); }
            }
          } catch (e) {}
        }
      });
    } catch (e) {}
  });

  function boot() {
    try {
      if (typeof Java === 'undefined' || !Java.available) { setImmediate(boot); return; }
      Java.perform(function () {
        try {
          var APM = Java.use('android.app.ApplicationPackageManager');
          APM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
            if (pkg === PKG && (flags & 0x40) !== 0) {
              stat.pkgHits++;
              log('getPackageInfo hit flags=' + flags + ' #' + stat.pkgHits);
            }
            return this.getPackageInfo(pkg, flags);
          };
          log('getPackageInfo hook installed');
        } catch (e) { log('hook err ' + e); }
      });
    } catch (e) { setImmediate(boot); }
  }
  boot();

  try {
    rpc.exports = {status: function () { return JSON.stringify(stat); }};
  } catch (e) {}
})();
