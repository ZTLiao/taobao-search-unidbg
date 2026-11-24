#!/usr/bin/env python3
"""生成 sg_sigspoof.js：把官方淘宝签名证书内嵌进 hook 脚本。

破解目标：重打包 APK 自签名 -> SecurityGuard 安全图片(yw_1222.jpg)解密失败
-> SecException 1927 -> authCode=null -> MTOP 签名失败(EC40002)。

原理：SG 用「当前 APK 签名证书」派生密钥去解密安全图片。只要 hook
PackageManager.getPackageInfo，让它在查询 com.taobao.taobao 的签名时返回
官方证书，SG 就能正常解密安全图片、生成 authCode，从而算出有效 x-sign。

这是低频 hook（只在 SG 初始化时调用几次），不保存 Java 对象引用跨帧，
因此不会触发 gadget 进程内 implementation hook 高频方法时的 JNI SIGABRT。

用法: python3 tools/frida/gen_sg_sigspoof.py
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CERT_HEX = os.path.join(HERE, '..', 'certs', 'official_cert.hex')
OUT = os.path.join(HERE, 'sg_sigspoof.js')


def main():
    with open(CERT_HEX, encoding='utf-8') as f:
        h = f.read().strip()
    der = bytes.fromhex(h)
    if len(der) != 583:
        raise SystemExit('证书 DER 长度异常: %d (期望 583)' % len(der))

    rows = []
    for i in range(0, len(der), 16):
        rows.append('    ' + ', '.join('0x%02x' % b for b in der[i:i + 16]))
    cert_js = ',\n'.join(rows)

    js = TEMPLATE.replace('__CERT_BYTES__', cert_js)
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write(js)
    print('written %s (%d bytes, cert=%d bytes)' % (OUT, os.path.getsize(OUT), len(der)))


TEMPLATE = r'''/**
 * sg_sigspoof.js —— SecurityGuard 签名身份 spoof（正面破解 1927）
 *
 * 由 tools/frida/gen_sg_sigspoof.py 生成，内嵌官方淘宝证书 DER（583 字节）。
 *
 * 破解链：
 *   重打包 APK 自签名 -> SG 用自签名派生密钥解不开 yw_1222.jpg
 *   -> SecException 1927 -> authCode=null -> getSecurityFactors 失败
 *   -> x-sign 生成失败 (EC40002)
 *   解决：让 SG 读到官方证书 -> 用官方密钥解密成功 -> authCode 正常 -> 出真签名
 *
 * 用法（gadget script-directory 模式，保证启动期就装 hook）：
 *   1) gadget config: {"interaction":{"type":"script-directory",
 *        "path":"/data/local/tmp/frida-scripts","on_change":"reload"}}
 *   2) adb push sg_sigspoof.js /data/local/tmp/frida-scripts/
 *   3) 重启 App；gadget 在 System.loadLibrary 时自动执行本脚本
 *
 * 关键：只在查询自身包名 + GET_SIGNATURES 时替换，且每次 new 独立 Signature
 * 数组，不保存跨帧 Java 引用 —— 规避 gadget 模式 JNI SIGABRT。
 */
(function () {
  var PKG = 'com.taobao.taobao';
  var FLAG_GET_SIGNATURES = 0x40;      // PackageManager.GET_SIGNATURES
  var FLAG_GET_SIGNING_CERT = 0x08000000; // GET_SIGNING_CERTIFICATES

  // 官方淘宝签名证书 DER（SHA1 4D:84:31:44:ED:57:7E:0A:2F:D7:B7:CC:13:DF:CC:C3:82:DF:49:7A）
  var OFFICIAL_CERT = [
__CERT_BYTES__
  ];

  var stat = {installed: false, hits: 0, flagsSeen: {}, errors: [], spoof: true};
  globalThis.__sgSpoof = stat;

  // script-directory 模式下 console.log 输出到 stdout（Android 上通常进 logcat，
  // 但 tag/可见性不确定）。用文件标记做可靠观测：每次写都重新打开文件，
  // 避免顶层极早期 File 失败后缓存 null 句柄导致后续全部静默。
  var STATUS_FILE = '/data/local/tmp/sg_spoof_status.txt';
  function log(s) {
    var line = '[SG-SPOOF] ' + s;
    console.log(line);
    try {
      var f = new File(STATUS_FILE, 'a');
      f.write(line + '\n');
      f.close();
    } catch (e) {}
  }
  function dumpStat(tag) {
    log(tag + ' installed=' + stat.installed + ' hits=' + stat.hits +
        ' spoof=' + stat.spoof + ' flags=' + JSON.stringify(stat.flagsSeen) +
        ' errors=' + JSON.stringify(stat.errors));
  }

  function install() {
    var Signature = null, APM = null;
    try {
      Signature = Java.use('android.content.pm.Signature');
      APM = Java.use('android.app.ApplicationPackageManager');
    } catch (e) {
      log('Java.use failed: ' + e);
      stat.errors.push('use: ' + e);
      return;
    }

    function officialSigArray() {
      var barr = Java.array('byte', OFFICIAL_CERT);
      var sig = Signature.$new(barr);
      return Java.array('android.content.pm.Signature', [sig]);
    }

    // ApplicationPackageManager.getPackageInfo(String, int) —— API 33 以下主路径
    try {
      APM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
        var res = this.getPackageInfo(pkg, flags);
        try {
          if (pkg === PKG && (flags & FLAG_GET_SIGNATURES) !== 0) {
            stat.hits++;
            var k = 'int:' + flags;
            stat.flagsSeen[k] = (stat.flagsSeen[k] || 0) + 1;
            if (stat.hits <= 8) log('hit getPackageInfo(int) flags=' + flags + ' spoof=' + stat.spoof);
            dumpStat('HIT');
            if (stat.spoof) res.signatures.value = officialSigArray();
          }
        } catch (e) {
          stat.errors.push('setSig: ' + e);
          if (stat.errors.length <= 5) log('set signatures error: ' + e);
        }
        return res;
      };
      log('hook getPackageInfo(String,int) OK');
    } catch (e) {
      stat.errors.push('hookInt: ' + e);
      log('hook int overload failed: ' + e);
    }

    // getPackageInfo(String, long) —— Android 13+ 重载，一并覆盖
    try {
      APM.getPackageInfo.overload('java.lang.String', 'long').implementation = function (pkg, flags) {
        var res = this.getPackageInfo(pkg, flags);
        try {
          var f = flags['longValue'] ? flags.longValue() : Number(flags);
          if (pkg === PKG && ((f & FLAG_GET_SIGNATURES) !== 0 || (f & FLAG_GET_SIGNING_CERT) !== 0)) {
            stat.hits++;
            var k2 = 'long:' + f;
            stat.flagsSeen[k2] = (stat.flagsSeen[k2] || 0) + 1;
            if (stat.hits <= 8) log('hit getPackageInfo(long) flags=' + f + ' spoof=' + stat.spoof);
            if (stat.spoof) {
              try { res.signatures.value = officialSigArray(); } catch (e) {}
            }
          }
        } catch (e) {
          stat.errors.push('setSigLong: ' + e);
        }
        return res;
      };
      log('hook getPackageInfo(String,long) OK');
    } catch (e) {
      log('no long overload (expected on API<33): ' + e);
    }

    stat.installed = true;
    log('installed. PKG=' + PKG + ' certBytes=' + OFFICIAL_CERT.length);
    dumpStat('INSTALLED');
  }

  var booted = false;
  function boot() {
    if (booted) return;
    // script-directory 模式下 gadget 在 loadLibrary 时就执行脚本，
    // 此刻 Java 全局对象可能尚未注入 —— 需等待其出现并可用。
    try {
      if (typeof Java === 'undefined' || !Java.available) {
        setTimeout(boot, 50);
        return;
      }
      booted = true;
      Java.perform(function () { install(); });
    } catch (e) {
      setTimeout(boot, 50);
    }
  }
  log('SCRIPT LOADED (booting)');
  boot();

  // Frida 17 gadget 的 script/script-directory 模式会调用 rpc.exports.init()，
  // 并等待其返回后才放行 App 入口 —— 这是保证 hook 赶在 SG 初始化前的正确时机。
  try {
    rpc.exports = {
      init: function (stage, parameters) {
        log('init() called stage=' + stage);
        if (!stat.installed) boot();
        // 给 hook 安装最多 3 秒的等待窗口
        return new Promise(function (resolve) {
          var n = 0;
          var t = setInterval(function () {
            if (stat.installed || ++n > 60) { clearInterval(t); resolve(); }
          }, 50);
        });
      },
      status: function () {
        return JSON.stringify({
          installed: stat.installed,
          hits: stat.hits,
          spoof: stat.spoof,
          flagsSeen: stat.flagsSeen,
          errors: stat.errors
        });
      },
      setSpoof: function (on) { stat.spoof = !!on; return String(stat.spoof); }
    };
  } catch (e) { log('rpc.exports err ' + e); }
})();
'''

if __name__ == '__main__':
    main()
