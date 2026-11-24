/**
 * sg_read_fulltrace.js —— 放宽版 SG 文件读取诊断（由 build_rpc_bundle.py 拼 bridge）
 *
 * 目的：IDA 静态确认 SG so 只 import 了 open/openat/__open_2/read/__read_chk/
 * fopen/fread/fstat/stat/access（无 mmap/pread/lseek）。此 hook 记录 libsgmainso
 * 相关的所有文件打开 + 读取，捕获 path/flags/offset/count/内容头部，
 * 判定 native open 重定向（曾 32→21）为何没完全破解 1927。
 *
 * 只诊断不改写，避免引入崩溃。
 */
(function () {
  var STATUS = '/data/local/tmp/sg_readtrace_status.txt';
  var stat = {opens: [], reads: [], fopens: [], errors: []};
  globalThis.__sgReadTrace = stat;

  function log(s) {
    console.log('[SG-RT] ' + s);
    try { var f = new File(STATUS, 'a'); f.write(s + '\n'); f.close(); } catch (e) {}
  }

  function callerModules(ctx) {
    var mods = [];
    try {
      var bt = Thread.backtrace(ctx, Backtracer.FUZZY);
      for (var i = 0; i < bt.length && i < 20; i++) {
        var m = Process.getModuleByAddress(bt[i]);
        if (m && mods.indexOf(m.name) < 0) mods.push(m.name);
      }
    } catch (e) {}
    return mods;
  }
  function isSG(mods) {
    for (var i = 0; i < mods.length; i++) {
      var m = mods[i].toLowerCase();
      if (m.indexOf('sgmain') >= 0) return true;
    }
    return false;
  }
  function interestingPath(p) {
    if (!p) return false;
    return p.indexOf('base.apk') >= 0 || p.indexOf('yw_1222') >= 0 ||
           p.indexOf('CERT.RSA') >= 0 || p.indexOf('META-INF') >= 0 ||
           p.indexOf('.apk') >= 0;
  }
  // main apk 的完整路径通常含包名；这里宽松匹配任意 base.apk
  function hexdump(p, n) {
    try { return hexdump_bytes(p.readByteArray(Math.min(n, 64))); } catch (e) { return ''; }
  }
  function hexdump_bytes(buf) {
    if (!buf) return '';
    var u = new Uint8Array(buf), s = '';
    for (var i = 0; i < u.length; i++) {
      var h = u[i].toString(16); if (h.length < 2) h = '0' + h;
      s += h;
    }
    return s;
  }

  var libc = Process.getModuleByName('libc.so');
  function exp(n) { try { return libc.getExportByName(n); } catch (e) { return null; } }

  // ---- open 家族：记录所有 sg 打开 apk/证书的路径和 flags ----
  [['open', 0, 1], ['open64', 0, 1], ['__open_2', 0, 1],
   ['openat', 1, 2], ['openat64', 1, 2], ['__openat_2', 1, 2]].forEach(function (spec) {
    var name = spec[0], pi = spec[1], fi = spec[2];
    var addr = exp(name); if (!addr) return;
    try {
      Interceptor.attach(addr, {
        onEnter: function (args) {
          this._sg = false;
          try {
            var p = args[pi].readCString() || '';
            if (!interestingPath(p)) return;
            var mods = callerModules(this.context);
            if (!isSG(mods)) return;
            this._sg = true;
            this._p = p;
            var flags = args[fi].toInt32();
            var rec = name + ' path=' + p + ' flags=0x' + (flags >>> 0).toString(16) +
                      ' mods=' + mods.slice(0, 4).join('/');
            if (stat.opens.length < 40) { stat.opens.push(rec); log('OPEN ' + rec); }
          } catch (e) {}
        },
        onLeave: function (ret) {
          if (!this._sg) return;
          try {
            var fd = ret.toInt32();
            if (stat.opens.length <= 40) log('  -> fd=' + fd + ' path=' + this._p);
          } catch (e) {}
        }
      });
      log('hooked ' + name + ' @' + addr);
    } catch (e) { stat.errors.push(name + ': ' + e); }
  });

  // ---- read / __read_chk：记录 sg 对 apk fd 的读取偏移与内容 ----
  // 这里无法直接拿到 fd→path 映射，改为：记录所有 read 的 fd/count/内容头，
  // 结合 open 阶段拿到的 fd 列表在 PC 端关联。
  function hookRead(name, bufIdx, cntIdx) {
    var addr = exp(name); if (!addr) return;
    try {
      Interceptor.attach(addr, {
        onEnter: function (args) {
          this._sg = false;
          try {
            var mods = callerModules(this.context);
            if (!isSG(mods)) return;
            this._sg = true;
            this._fd = args[0].toInt32();
            this._cnt = args[cntIdx].toInt32();
            this._buf = args[bufIdx];
          } catch (e) {}
        },
        onLeave: function (ret) {
          if (!this._sg) return;
          try {
            var n = ret.toInt32();
            if (n <= 0) return;
            // 只记录较大的读取（签名块/证书通常上百字节），跳过零散小读
            if (this._cnt < 64) return;
            var head = hexdump(this._buf, 32);
            var rec = name + ' fd=' + this._fd + ' cnt=' + this._cnt + ' ret=' + n + ' head=' + head;
            if (stat.reads.length < 120) { stat.reads.push(rec); log('READ ' + rec); }
          } catch (e) {}
        }
      });
      log('hooked ' + name + ' @' + addr);
    } catch (e) { stat.errors.push(name + ': ' + e); }
  }
  hookRead('read', 1, 2);
  hookRead('__read_chk', 1, 2);

  // ---- fopen / fread：stdio 路径 ----
  var fopen = exp('fopen');
  if (fopen) {
    try {
      Interceptor.attach(fopen, {
        onEnter: function (args) {
          this._sg = false;
          try {
            var p = args[0].readCString() || '';
            if (!interestingPath(p)) return;
            var mods = callerModules(this.context);
            if (!isSG(mods)) return;
            this._sg = true;
            var rec = 'fopen path=' + p + ' mode=' + (args[1].readCString() || '') +
                      ' mods=' + mods.slice(0, 4).join('/');
            if (stat.fopens.length < 40) { stat.fopens.push(rec); log('FOPEN ' + rec); }
          } catch (e) {}
        }
      });
      log('hooked fopen @' + fopen);
    } catch (e) { stat.errors.push('fopen: ' + e); }
  }

  try {
    rpc.exports = {
      init: function () { return Promise.resolve(); },
      status: function () { return JSON.stringify(stat); }
    };
  } catch (e) {}
})();
