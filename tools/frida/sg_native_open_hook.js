/**
 * sg_native_open_hook.js —— 破解 SG 1927 的 native 层签名读取（hook open/openat）
 *
 * 背景：
 *   sg_sigspoof.js 只 spoof 了 Java 层 getPackageInfo(GET_SIGNATURES)，命中 23 次，
 *   但 1927 仍出现 35 次。日志栈显示 SG 通过
 *     libcore.io.Linux.open(Native Method)
 *     com.alibaba.wireless.security.adapter.JNICLibrary.doCommandNative(Native Method)
 *   直接在 native 层打开 /data/app/.../base.apk 读取签名块 / 安全图片，
 *   拿到的是重打包自签名，导致 yw_1222.jpg 解密失败 -> 1927。
 *
 * 本脚本两级能力（由设备文件开关控制，可用同一 bundle 跑两种模式）：
 *   1) PROBE 模式（默认）：dump 所有命中 APK/签名关键字的 open/openat：
 *        path / flags / tid / 返回 fd / 调用方模块。
 *      用来确认 SG 到底 open 了哪个路径。
 *   2) REDIRECT 模式：在 onEnter 把「重打包 base.apk」的路径替换为
 *        /data/local/tmp/official_base.apk（官方签名 APK），
 *      让 SG 读到官方证书 -> 用官方密钥解密安全图片 -> 1927 消失。
 *      开关：adb shell touch /data/local/tmp/sg_open_redirect.flag
 *
 * 加载方式：listen + on_load="wait" gadget，race attach（见 race_attach_native_open.py）。
 *   这样 hook 在 SG 初始化前就装好。
 */
(function () {
  var PKG = 'com.taobao.taobao';
  var OFFICIAL_APK = '/data/local/tmp/official_base.apk';
  var REDIRECT_FLAG = '/data/local/tmp/sg_open_redirect.flag';
  var STATUS_FILE = '/data/local/tmp/sg_native_open_status.txt';

  var stat = {
    loaded: false,
    installed: false,
    redirect: false,
    opens: [],          // 命中的 open 记录
    redirectHits: 0,
    pkgHits: 0,
    errors: [],
    maxOpens: 300
  };
  globalThis.__sgNativeOpen = stat;

  function log(s) {
    var line = '[SG-NOPEN] ' + s;
    console.log(line);
    try {
      var f = new File(STATUS_FILE, 'a');
      f.write(line + '\n');
      f.close();
    } catch (e) {}
  }

  function fileExists(p) {
    try {
      var f = new File(p, 'r');
      f.close();
      return true;
    } catch (e) {
      return false;
    }
  }

  try { stat.redirect = fileExists(REDIRECT_FLAG); } catch (e) {}
  log('SCRIPT LOADED redirect=' + stat.redirect + ' officialApk=' + OFFICIAL_APK);

  function interesting(p) {
    if (!p) return false;
    // 不要匹配 PKG —— app_SGLib 下所有路径都含包名，会产生海量日志
    return p.indexOf('base.apk') >= 0 ||
           p.indexOf('CERT.RSA') >= 0 ||
           p.indexOf('yw_1222') >= 0 ||
           p.indexOf('META-INF/') >= 0 ||
           p.indexOf('.apk') >= 0;
  }

  // bionic 里 open/openat 有多个别名/64 位变体，按地址去重避免重复记录
  // [导出名, path 参数下标, flags 参数下标]
  var OPEN_FNS = [
    ['open',      0, 1],
    ['open64',    0, 1],
    ['__open',    0, 1],
    ['__open_2',  0, 1],
    ['openat',    1, 2],
    ['openat64',  1, 2],
    ['__openat',  1, 2],
    ['__openat_2', 1, 2]
  ];

  function callerModule() {
    try {
      var bt = Thread.backtrace(this.context, Backtracer.FUZZY);
      if (bt && bt.length) {
        // 跳过 libc/linker 自身，找到真正的调用方 so（通常是 libsgmain.so）
        for (var i = 0; i < bt.length && i < 12; i++) {
          var m = Process.getModuleByAddress(bt[i]);
          if (m && m.name !== 'libc.so' && m.name.indexOf('linker') < 0) {
            return m.name;
          }
        }
      }
    } catch (e) {}
    return '?';
  }

  function hookOpen() {
    var seenAddr = {};
    // Frida 17 移除了静态 Module.findExportByName，改用模块实例 API
    var libc = Process.getModuleByName('libc.so');
    OPEN_FNS.forEach(function (spec) {
      var name = spec[0], pathIdx = spec[1], flagsIdx = spec[2];
      try {
        var addr = null;
        try { addr = libc.getExportByName(name); } catch (e) {}
        if (!addr) return;
        var key = addr.toString();
        if (seenAddr[key]) {
          log('skip alias ' + name + '@' + addr + ' (same address as earlier)');
          return;
        }
        seenAddr[key] = true;

        Interceptor.attach(addr, {
          onEnter: function (args) {
            try {
              var p = args[pathIdx].readCString() || '';
              if (!interesting(p)) return;
              var flags = args[flagsIdx].toInt32();
              var tid = Process.getCurrentThreadId();
              var caller = callerModule.call(this);
              var isBase = p.indexOf('base.apk') >= 0 && p.indexOf(PKG) >= 0;
              // 精准判定：只有 libsgmainso 以 O_RDONLY(0x0) 打开淘宝 base.apk 才是
              // SG 读签名。libjavacore/libart/webview 也会开 base.apk（flags 0x80000/
              // 0x280000 或别的包名），绝不能重定向，否则破坏资源/DEX 加载。
              var isSGRead = isBase && flags === 0 &&
                             caller.indexOf('libsgmainso') >= 0;
              var rec = name + ' path=' + p + ' flags=0x' + (flags >>> 0).toString(16) +
                        ' tid=' + tid + ' caller=' + caller +
                        ' base=' + isBase + ' SGREAD=' + isSGRead;
              if (stat.opens.length < stat.maxOpens) {
                stat.opens.push(rec);
                log('OPEN ' + rec);
              }
              // REDIRECT：SG 读签名用的 base.apk -> 官方 APK（官方签名）
              if (stat.redirect && isSGRead) {
                this._newPath = Memory.allocUtf8String(OFFICIAL_APK);
                args[pathIdx] = this._newPath;
                stat.redirectHits++;
                log('REDIRECT #' + stat.redirectHits + ' ' + p + ' -> ' + OFFICIAL_APK);
              }
            } catch (e) {}
          },
          onLeave: function (retval) {
            try {
              if (this._newPath) {
                log('REDIRECT fd=' + retval.toInt32() + ' (0/-1 means failed)');
              }
            } catch (e) {}
          }
        });
        log('hooked ' + name + '@' + addr);
      } catch (e) {
        stat.errors.push('hook ' + name + ': ' + e);
        log('hook ' + name + ' ERROR ' + e);
      }
    });
    stat.installed = true;
    log('native open hooks installed installed=' + stat.installed);
  }

  // native hook 不依赖 Java VM，脚本加载即装
  hookOpen();

  // Java 层 getPackageInfo 作为对照（只记录，不 spoof —— 隔离验证 native 路径）
  function boot() {
    try {
      if (typeof Java === 'undefined' || !Java.available) {
        setTimeout(boot, 50);
        return;
      }
      Java.perform(function () {
        try {
          var APM = Java.use('android.app.ApplicationPackageManager');
          APM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
            var res = this.getPackageInfo(pkg, flags);
            try {
              if (pkg === PKG && (flags & 0x40) !== 0) {
                stat.pkgHits++;
                if (stat.pkgHits <= 5) log('getPackageInfo hit flags=' + flags + ' #' + stat.pkgHits);
              }
            } catch (e) {}
            return res;
          };
          log('getPackageInfo control hook installed');
        } catch (e) {
          stat.errors.push('java: ' + e);
          log('java hook ERROR ' + e);
        }
      });
    } catch (e) {
      setTimeout(boot, 50);
    }
  }
  boot();

  stat.loaded = true;

  try {
    rpc.exports = {
      init: function (stage, parameters) {
        log('init() called stage=' + stage + ' redirect=' + stat.redirect);
        return new Promise(function (resolve) {
          var n = 0;
          var t = setInterval(function () {
            if (stat.installed || ++n > 40) { clearInterval(t); resolve(); }
          }, 50);
        });
      },
      status: function () { return JSON.stringify(stat); },
      setRedirect: function (on) {
        stat.redirect = !!on;
        return String(stat.redirect);
      }
    };
  } catch (e) {
    log('rpc.exports ERROR ' + e);
  }
})();
