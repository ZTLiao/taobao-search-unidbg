#!/usr/bin/env python3
"""生成 sg_sig_full.js：把官方证书 DER 注入三路签名 spoof hook。

三路（SG 读签名的所有已知路径）：
  1) getPackageInfo(String,int/long) → 替换 signatures + signingInfo.apkContentsSigners
  2) Signature.toByteArray() → 直接返回官方证书 DER（SG 真正取证书字节的地方）
  3) native open/openat → 把 libsgmainso 读的重打包 base.apk 重定向到官方 APK
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, '..', 'certs', 'official_cert_frida.txt')
OUT = os.path.join(HERE, 'sg_sig_full.js')

cert = open(CERT, encoding='utf-8').read().strip()

JS = r'''/**
 * sg_sig_full.js —— 官方证书固定（三路 hook，破解重打包 1927）
 * 由 tools/frida/gen_sg_sig_full.py 生成，内嵌官方证书 DER。
 *
 * 目标：让 SecurityGuard 无论从哪条路径读签名，都拿到官方签名身份。
 *   1) Signature.toByteArray() → 官方证书 DER（Java 层最底层字节来源）
 *   2) native open/openat → SG 读的 base.apk 重定向到官方 APK
 * 注：getPackageInfo hook 已移除 —— 返回后访问系统 PackageInfo 字段会
 *     触发 JNI 局部引用跨帧失效 → SIGABRT（GetStringChars invalid jstring）。
 */
(function () {
  var PKG = 'com.taobao.taobao';
  var OFFICIAL_APK = '/data/local/tmp/official_base.apk';
  var STATUS_FILE = '/data/local/tmp/sg_sigfull_status.txt';
  var FLAG_SIG = 0x40;            // GET_SIGNATURES
  var FLAG_SIGNING_CERT = 0x08000000; // GET_SIGNING_CERTIFICATES

  var OFFICIAL_CERT = [__CERT__];

  var stat = {installed: false, javaPkgHits: 0, toByteArrayHits: 0,
              nativeRedirects: 0, errors: [], certLen: OFFICIAL_CERT.length};
  globalThis.__sgSigFull = stat;

  function log(s) {
    var line = '[SG-FULL] ' + s;
    console.log(line);
    try { var f = new File(STATUS_FILE, 'a'); f.write(line + '\n'); f.close(); } catch (e) {}
  }

  // ---------- native: open/openat 重定向 ----------
  var libc = Process.getModuleByName('libc.so');
  function exp(n) { try { return libc.getExportByName(n); } catch (e) { return null; } }
  function callerModule(ctx) {
    try {
      var bt = Thread.backtrace(ctx, Backtracer.FUZZY);
      for (var i = 0; i < bt.length && i < 14; i++) {
        var m = Process.getModuleByAddress(bt[i]);
        if (m && m.name !== 'libc.so' && m.name.indexOf('linker') < 0) return m.name;
      }
    } catch (e) {}
    return '?';
  }
  [['open', 0, 1], ['openat', 1, 2], ['__open_2', 0, 1], ['__openat_2', 1, 2]].forEach(function (spec) {
    var name = spec[0], pi = spec[1], fi = spec[2];
    var addr = exp(name);
    if (!addr) return;
    try {
      Interceptor.attach(addr, {
        onEnter: function (args) {
          this._redo = false;
          try {
            var p = args[pi].readCString() || '';
            var flags = args[fi].toInt32();
            var caller = callerModule(this.context);
            if (p.indexOf('base.apk') >= 0 && p.indexOf(PKG) >= 0 &&
                flags === 0 && caller.indexOf('libsgmainso') >= 0) {
              this._redo = true;
              stat.nativeRedirects++;
              if (stat.nativeRedirects <= 5) log('native redirect ' + p + ' -> ' + OFFICIAL_APK);
              this._newPath = Memory.allocUtf8String(OFFICIAL_APK);
              args[pi] = this._newPath;
            }
          } catch (e) {}
        }
      });
      log('native hook ' + name + ' @' + addr);
    } catch (e) { stat.errors.push('native ' + name + ': ' + e); }
  });

  // ---------- Java: getPackageInfo + Signature.toByteArray ----------
  function boot() {
    try {
      if (typeof Java === 'undefined' || !Java.available) { setTimeout(boot, 50); return; }
      Java.perform(function () {
        var Signature = Java.use('android.content.pm.Signature');

        // 路2（核心）：Signature.toByteArray —— SG 取证书字节的最底层。
        // 只返回一个新建的 byte 数组，绝不触碰系统 PackageInfo/SigningInfo 对象字段，
        // 避免 JNI 局部引用跨帧失效导致 SIGABRT（GetStringChars on invalid jstring）。
        try {
          Signature.toByteArray.implementation = function () {
            stat.toByteArrayHits++;
            if (stat.toByteArrayHits <= 8) log('toByteArray hit #' + stat.toByteArrayHits);
            return Java.array('byte', OFFICIAL_CERT);
          };
          log('hook Signature.toByteArray OK');
        } catch (e) { stat.errors.push('toByteArray: ' + e); log('toByteArray hook err ' + e); }

        // 路1 已移除：getPackageInfo hook 会在返回后访问系统 PackageInfo 的
        // signatures/signingInfo 字段，JNI 局部引用跨帧失效 → SIGABRT。
        // 证书字节已在 toByteArray 层统一替换，无需碰 getPackageInfo。

        stat.installed = true;
        log('INSTALLED certLen=' + OFFICIAL_CERT.length);
      });
    } catch (e) { setTimeout(boot, 50); }
  }
  boot();

  try {
    rpc.exports = {
      init: function (stage) { return Promise.resolve(); },
      status: function () { return JSON.stringify(stat); }
    };
  } catch (e) {}
})();
'''.replace('__CERT__', cert)

open(OUT, 'w', encoding='utf-8').write(JS)
print('written %s (%d bytes, cert %d bytes)' % (OUT, os.path.getsize(OUT), len(cert.split(','))))
