/**
 * sg_read_trace.js —— 追踪 SG 打开 base.apk 后到底怎么读签名
 *
 * 背景：redirect base.apk -> 官方 APK 后 1927 仅 32->21，未消除。
 *       怀疑 SG 不是简单 read 整个文件，而是 mmap + 偏移 / pread 固定偏移
 *       读取签名块。官方 APK 95MB vs 重打包 108MB，布局不同 -> 偏移读错。
 *
 * Hook：
 *   - open/openat：记录 libsgmainso 以 O_RDONLY 打开 base.apk 得到的 fd
 *   - read / pread64 / lseek64 / mmap64：只追踪上述 fd，记录 offset/len/内容
 */
(function () {
  var PKG = 'com.taobao.taobao';
  var STATUS_FILE = '/data/local/tmp/sg_read_trace_status.txt';
  var sgFds = {};         // fd -> true（SG 打开的 base.apk）
  var stat = {opens: 0, reads: 0, preads: 0, seeks: 0, mmaps: 0, records: [], errors: []};
  globalThis.__sgReadTrace = stat;

  function log(s) {
    var line = '[SG-RTRACE] ' + s;
    console.log(line);
    try { var f = new File(STATUS_FILE, 'a'); f.write(line + '\n'); f.close(); } catch (e) {}
  }
  function rec(s) {
    if (stat.records.length < 120) { stat.records.push(s); log(s); }
  }
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

  var libc = Process.getModuleByName('libc.so');
  function exp(n) { try { return libc.getExportByName(n); } catch (e) { return null; } }

  // ---- open/openat：捕获 SG 读 base.apk 的 fd ----
  [['open', 0, 1], ['openat', 1, 2], ['__open_2', 0, 1], ['__openat_2', 1, 2]].forEach(function (spec) {
    var name = spec[0], pi = spec[1], fi = spec[2];
    var addr = exp(name);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this._track = false;
        try {
          var p = args[pi].readCString() || '';
          var flags = args[fi].toInt32();
          var caller = callerModule(this.context);
          if (p.indexOf('base.apk') >= 0 && p.indexOf(PKG) >= 0 &&
              flags === 0 && caller.indexOf('libsgmainso') >= 0) {
            this._track = true;
          }
        } catch (e) {}
      },
      onLeave: function (retval) {
        if (!this._track) return;
        try {
          var fd = retval.toInt32();
          if (fd > 0) { sgFds[fd] = true; stat.opens++; rec('OPEN base.apk fd=' + fd); }
        } catch (e) {}
      }
    });
  });

  // ---- read(fd, buf, count) ----
  var readAddr = exp('read');
  if (readAddr) {
    Interceptor.attach(readAddr, {
      onEnter: function (args) {
        this._fd = args[0].toInt32();
        this._buf = args[1];
        this._count = args[2].toInt32();
      },
      onLeave: function (retval) {
        if (!sgFds[this._fd]) return;
        var n = retval.toInt32();
        stat.reads++;
        var head = '';
        if (n > 0) { try { head = hex(this._buf.readByteArray(Math.min(n, 24))); } catch (e) {} }
        if (stat.reads <= 40) rec('READ fd=' + this._fd + ' count=' + this._count + ' ret=' + n + ' head=' + head);
      }
    });
  }

  // ---- pread64(fd, buf, count, offset) ----
  var preadAddr = exp('pread64') || exp('pread');
  if (preadAddr) {
    Interceptor.attach(preadAddr, {
      onEnter: function (args) {
        this._fd = args[0].toInt32();
        this._buf = args[1];
        this._count = args[2].toInt32();
        try { this._off = args[3].toInt64(); } catch (e) { this._off = 0; }
      },
      onLeave: function (retval) {
        if (!sgFds[this._fd]) return;
        var n = retval.toInt32();
        stat.preads++;
        var head = '';
        if (n > 0) { try { head = hex(this._buf.readByteArray(Math.min(n, 24))); } catch (e) {} }
        if (stat.preads <= 40) rec('PREAD fd=' + this._fd + ' off=' + this._off + ' count=' + this._count + ' ret=' + n + ' head=' + head);
      }
    });
  }

  // ---- lseek64(fd, offset, whence) ----
  var lseekAddr = exp('lseek64') || exp('lseek');
  if (lseekAddr) {
    Interceptor.attach(lseekAddr, {
      onEnter: function (args) {
        this._fd = args[0].toInt32();
        try { this._off = args[1].toInt64(); } catch (e) { this._off = 0; }
        this._whence = args[2].toInt32();
      },
      onLeave: function (retval) {
        if (!sgFds[this._fd]) return;
        stat.seeks++;
        if (stat.seeks <= 30) rec('LSEEK fd=' + this._fd + ' off=' + this._off + ' whence=' + this._whence);
      }
    });
  }

  // ---- mmap64(addr, len, prot, flags, fd, offset) ----
  var mmapAddr = exp('mmap64') || exp('mmap');
  if (mmapAddr) {
    Interceptor.attach(mmapAddr, {
      onEnter: function (args) {
        this._fd = args[4].toInt32();
        this._len = args[1].toInt32();
        try { this._off = args[5].toInt64(); } catch (e) { this._off = 0; }
        this._prot = args[2].toInt32();
      },
      onLeave: function (retval) {
        if (!sgFds[this._fd]) return;
        stat.mmaps++;
        rec('MMAP fd=' + this._fd + ' len=' + this._len + ' off=' + this._off + ' prot=0x' + this._prot.toString(16) + ' ret=' + retval);
      }
    });
  }

  function hex(buf) {
    if (!buf) return '';
    var u = new Uint8Array(buf), s = '';
    for (var i = 0; i < u.length; i++) s += ('0' + u[i].toString(16)).slice(-2);
    return s;
  }

  log('SCRIPT LOADED. libc=' + libc.name);
  try {
    rpc.exports = {
      init: function (stage) { return Promise.resolve(); },
      status: function () { return JSON.stringify(stat); }
    };
  } catch (e) {}
})();
