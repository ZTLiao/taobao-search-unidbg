/**
 * sg_syscall_hook.js —— hook libsgmainso 内嵌的 svc syscall 指令（由 build_rpc_bundle 拼 bridge）
 *
 * 决定性依据：so 含 1099 条 svc #0，IDA 定位其中 6 条 __NR_openat(56) 的 svc 指令：
 *   文件偏移 0xa9170, 0xb2ae8, 0x1171bc, 0x160d40, 0x192620, 0x1a4154
 *   ARM64 openat(dirfd=x0, path=x1, flags=x2) —— svc 前读 x1 即真实路径。
 *
 * MODE 由 /data/local/tmp/sg_syscall_mode.txt 控制：
 *   PROBE（默认）：记录每条 svc 的 x1 路径 / x0 dirfd / x2 flags，不改写
 *   REDIRECT     ：若 x1 路径含 base.apk+包名，替换为官方 APK 路径
 */
(function () {
  var STATUS = '/data/local/tmp/sg_syscall_status.txt';
  var MODENAME = '/data/local/tmp/sg_syscall_mode.txt';
  var PKG = 'com.taobao.taobao';
  var OFFICIAL = '/data/local/tmp/official_base.apk';

  // IDA 定位的 openat svc 文件偏移
  var SVC_OFFSETS = [0xa9170, 0xb2ae8, 0x1171bc, 0x160d40, 0x192620, 0x1a4154];
  // 也纳入 read(63)/pread64(17) 便于观察签名块读取（只读诊断）
  var READ_OFFSETS = [0x6960c, 0x8ee40, 0xc50f8, 0x116b20, 0x11f010, 0x121404, 0x1af740];

  var stat = {mode: 'PROBE', hooked: [], openEvents: [], redirects: 0, errors: []};
  globalThis.__sgSyscall = stat;

  function log(s) {
    console.log('[SG-SYS] ' + s);
    try { var f = new File(STATUS, 'a'); f.write(s + '\n'); f.close(); } catch (e) {}
  }
  function readMode() {
    try {
      var f = new File(MODENAME, 'r'); var s = f.readText(); f.close();
      return (s || '').trim().toUpperCase() === 'REDIRECT' ? 'REDIRECT' : 'PROBE';
    } catch (e) { return 'PROBE'; }
  }
  stat.mode = readMode();
  log('MODE=' + stat.mode);

  // libsgmainso 模块基址（运行时）
  var mod = null;
  try {
    mod = Process.getModuleByName('libsgmainso-6.8.260901.so');
  } catch (e) {
    // 尝试枚举包含 sgmainso 的模块
    try {
      var mods = Process.enumerateModules();
      for (var i = 0; i < mods.length; i++) {
        if (mods[i].name.indexOf('sgmainso') >= 0) { mod = mods[i]; break; }
      }
    } catch (e2) {}
  }
  if (!mod) { log('ERROR: libsgmainso module NOT FOUND'); return; }
  log('module base=' + mod.base + ' path=' + mod.path);

  function safeCString(ptr) {
    try { return ptr.readCString() || ''; } catch (e) { return '<invalid>'; }
  }

  // openat svc hook：在 svc 指令处 attach，读 x1=path
  SVC_OFFSETS.forEach(function (off) {
    var addr = mod.base.add(off);
    try {
      Interceptor.attach(addr, {
        onEnter: function (args) {
          var ctx = this.context;
          var dirfd = ctx.x0.toInt32();
          var pathPtr = ctx.x1;
          var flags = ctx.x2.toInt32();
          var scNum = ctx.x8.toInt32();
          var path = safeCString(pathPtr);
          // 只记录 sg 相关的 apk/证书路径
          if (path.indexOf('base.apk') >= 0 || path.indexOf(PKG) >= 0 ||
              path.indexOf('yw_1222') >= 0 || path.indexOf('CERT') >= 0) {
            var rec = 'SVC@0x' + off.toString(16) + ' sc=' + scNum +
                      ' openat(dirfd=' + dirfd + ', flags=0x' + (flags >>> 0).toString(16) +
                      ') path=' + path;
            stat.openEvents.push(rec);
            log(rec);
            // REDIRECT：替换 x1 指向官方 APK
            if (stat.mode === 'REDIRECT' && path.indexOf('base.apk') >= 0 &&
                path.indexOf(PKG) >= 0) {
              this._newp = Memory.allocUtf8String(OFFICIAL);
              ctx.x1 = this._newp;
              stat.redirects++;
              log('  >>> REDIRECT x1 -> ' + OFFICIAL);
            }
          }
        }
      });
      stat.hooked.push('openat@0x' + off.toString(16));
      log('hooked openat svc @0x' + off.toString(16) + ' addr=' + addr);
    } catch (e) { stat.errors.push('openat@0x' + off.toString(16) + ': ' + e); log('hook err @' + off.toString(16) + ': ' + e); }
  });

  // read/pread svc hook：只诊断（记录 fd=x0, count=x2），不改写
  READ_OFFSETS.forEach(function (off) {
    var addr = mod.base.add(off);
    try {
      Interceptor.attach(addr, {
        onEnter: function () {
          var ctx = this.context;
          var fd = ctx.x0.toInt32();
          var cnt = ctx.x2.toInt32();
          var scNum = ctx.x8.toInt32();
          // 只记录较大读取（签名块/证书）
          if (cnt >= 256) {
            log('READ_SVC@0x' + off.toString(16) + ' sc=' + scNum + ' fd=' + fd + ' cnt=' + cnt);
          }
        }
      });
      stat.hooked.push('read@0x' + off.toString(16));
    } catch (e) { stat.errors.push('read@0x' + off.toString(16) + ': ' + e); }
  });

  try {
    rpc.exports = {
      init: function () { return Promise.resolve(); },
      status: function () { return JSON.stringify(stat); }
    };
  } catch (e) {}
})();
