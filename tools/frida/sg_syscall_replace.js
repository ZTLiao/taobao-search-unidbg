/**
 * sg_syscall_replace.js —— 最终方案：replace svc openat wrapper，透传 libc.openat + 路径重定向。
 *
 * 依据：IDA 定位 libsgmainso 内 6 条 __NR_openat(56) 的 `svc #0; ret` wrapper
 *   （文件偏移 0xa9170,0xb2ae8,0x1171bc,0x160d40,0x192620,0x1a4154）。
 *   Interceptor.attach 无法挂内联 svc，但 Interceptor.replace 可以。
 * 策略：把 wrapper 替换为 NativeCallback，内部调用 libc.openat 透传原语义，
 *   若路径是重打包 base.apk → 换成官方 APK。避免像 return 0 那样破坏 App。
 *
 * MODE 由 /data/local/tmp/sg_syscall_mode.txt 控制：PROBE(默认) / REDIRECT
 */
(function () {
  var STATUS = '/data/local/tmp/sg_syscall_status.txt';
  var MODEF = '/data/local/tmp/sg_syscall_mode.txt';
  var PKG = 'com.taobao.taobao';
  var OFFICIAL = '/data/local/tmp/official_base.apk';
  var OFFS = [0xa9170, 0xb2ae8, 0x1171bc, 0x160d40, 0x192620, 0x1a4154];

  var stat = {mode: 'PROBE', base: null, installed: [], calls: 0, apkHits: 0,
              redirects: 0, errors: []};
  globalThis.__sgSysRep = stat;
  function log(s) {
    console.log('[SG-SR] ' + s);
    try { var f = new File(STATUS, 'a'); f.write(s + '\n'); f.close(); } catch (e) {}
  }
  function readMode() {
    try { var f = new File(MODEF, 'r'); var s = f.readText(); f.close();
      return (s || '').trim().toUpperCase() === 'REDIRECT' ? 'REDIRECT' : 'PROBE';
    } catch (e) { return 'PROBE'; }
  }
  stat.mode = readMode();

  function findMod() {
    try {
      var mods = Process.enumerateModules();
      for (var i = 0; i < mods.length; i++)
        if (mods[i].name.indexOf('sgmainso') >= 0) return mods[i];
    } catch (e) {}
    return null;
  }

  // libc.openat 用于透传：int openat(int dirfd, const char* path, int flags, mode_t mode)
  var libc = Process.getModuleByName('libc.so');
  var openatFn = new NativeFunction(libc.getExportByName('openat'), 'int',
                                    ['int', 'pointer', 'int', 'uint']);
  var errnoLoc = null;
  try { errnoLoc = libc.getExportByName('__errno'); } catch (e) {}

  function install() {
    var mod = findMod();
    if (!mod) { stat.errors.push('module not loaded at install time'); log('module NOT loaded'); return; }
    stat.base = mod.base.toString();
    log('module ready base=' + mod.base + ' MODE=' + stat.mode);
    OFFS.forEach(function (off) {
      var addr = mod.base.add(off);
      try {
        var cb = new NativeCallback(function (dirfd, pathPtr, flags, mode) {
          stat.calls++;
          var path = '';
          try { path = pathPtr.readCString() || ''; } catch (e) {}
          var isApk = path.indexOf('base.apk') >= 0 && path.indexOf(PKG) >= 0;
          var usePath = path;
          if (isApk) {
            stat.apkHits++;
            if (stat.apkHits <= 10) log('APK openat off=0x' + off.toString(16) +
                                        ' path=' + path + ' flags=0x' + (flags >>> 0).toString(16));
            if (stat.mode === 'REDIRECT') {
              usePath = OFFICIAL;
              stat.redirects++;
            }
          }
          var newPtr = (isApk && stat.mode === 'REDIRECT')
            ? Memory.allocUtf8String(usePath) : pathPtr;
          // 透传真实 syscall
          return openatFn(dirfd, newPtr, flags, mode);
        }, 'int', ['int', 'pointer', 'int', 'uint']);
        Interceptor.replace(addr, cb);
        stat.installed.push('0x' + off.toString(16));
        log('installed svc openat replace @0x' + off.toString(16));
      } catch (e) {
        stat.errors.push('0x' + off.toString(16) + ': ' + e);
        log('replace FAIL @0x' + off.toString(16) + ': ' + e);
      }
    });
    log('ALL INSTALLED calls tracking started');
  }
  install();

  try {
    rpc.exports = {
      init: function () { return Promise.resolve(); },
      status: function () { return JSON.stringify(stat); }
    };
  } catch (e) {}
})();
