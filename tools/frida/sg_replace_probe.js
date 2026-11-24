/**
 * sg_replace_probe.js —— 实验：用 Interceptor.replace hook svc wrapper，打印参数判断 syscall 类型
 */
(function () {
  var STATUS = '/data/local/tmp/sg_replace_status.txt';
  function log(s) {
    console.log('[SG-RP] ' + s);
    try { var f = new File(STATUS, 'a'); f.write(s + '\n'); f.close(); } catch (e) {}
  }
  var mod = null;
  function findMod() {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      if (mods[i].name.indexOf('sgmainso') >= 0) return mods[i];
    }
    return null;
  }
  mod = findMod();
  if (!mod) log('module not yet loaded, will poll...');

  // ARM64 调用约定：NativeCallback 收到 x0..x7。openat(x0=dirfd,x1=path,x2=flags,x3=mode)
  var OFFS = [0xa9170, 0xb2ae8, 0x1171bc, 0x160d40, 0x192620, 0x1a4154];
  var counts = {};
  var installed = false;
  function install() {
    if (installed) return;
    mod = mod || findMod();
    if (!mod) { setTimeout(install, 10); return; }
    installed = true;
    log('base=' + mod.base + ' module ready, installing svc hooks');
    OFFS.forEach(function (off) {
      var addr = mod.base.add(off);
      counts[off] = 0;
      try {
        var cb = new NativeCallback(function (a0, a1, a2, a3, a4, a5) {
          counts[off]++;
          if (counts[off] <= 6) {
            var p1 = '';
            try { p1 = ptr(a1).readCString() || ''; } catch (e) { p1 = '<not-string>'; }
            log('CALL off=0x' + off.toString(16) + ' #' + counts[off] +
                ' a0=0x' + ptr(a0).toString(16) +
                ' a1=0x' + ptr(a1).toString(16) + ' str=[' + p1.substring(0, 90) + ']' +
                ' a2=0x' + ptr(a2).toString(16) + ' a3=0x' + ptr(a3).toString(16));
          }
          return 0;
        }, 'int', ['int', 'int', 'int', 'int', 'int', 'int']);
        Interceptor.replace(addr, cb);
        log('REPLACED off=0x' + off.toString(16) + ' @' + addr);
      } catch (e) {
        log('replace FAIL off=0x' + off.toString(16) + ': ' + e);
      }
    });
  }
  install();

  try {
    rpc.exports = {
      init: function () { return Promise.resolve(); },
      status: function () { return JSON.stringify(counts); }
    };
  } catch (e) {}
})();
