/**
 * sg_memdump.js —— 诊断运行时 svc 地址是否真实（应对加固 so 自解密）
 */
(function () {
  var STATUS = '/data/local/tmp/sg_memdump_status.txt';
  function log(s) {
    console.log('[SG-DUMP] ' + s);
    try { var f = new File(STATUS, 'a'); f.write(s + '\n'); f.close(); } catch (e) {}
  }
  var mod = null;
  var mods = Process.enumerateModules();
  for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.indexOf('sgmainso') >= 0) { mod = mods[i]; break; }
  }
  if (!mod) { log('module not found'); return; }
  log('base=' + mod.base + ' size=' + mod.size + ' path=' + mod.path);

  // 硬编码的 svc 文件偏移（IDA 定位的 openat）
  var OFFS = [0xa9170, 0xb2ae8, 0x1171bc, 0x160d40, 0x192620, 0x1a4154];
  OFFS.forEach(function (off) {
    var addr = mod.base.add(off);
    try {
      var b = addr.readByteArray(16);
      var u = new Uint8Array(b), hex = '';
      for (var j = 0; j < u.length; j++) {
        var h = u[j].toString(16); if (h.length < 2) h = '0' + h;
        hex += h + ' ';
      }
      log('off=0x' + off.toString(16) + ' addr=' + addr + ' bytes=' + hex);
    } catch (e) { log('off=0x' + off.toString(16) + ' ERR ' + e); }
  });

  // 动态搜索：在模块代码段里扫描 svc #0 (01 00 00 D4 LE) 出现次数
  // 只扫可执行段，限制数量避免卡死
  try {
    var ranges = mod.enumerateRanges('r-x');
    var total = 0, samples = [];
    ranges.forEach(function (r) {
      try {
        var buf = r.base.readByteArray(r.size);
        var u = new Uint8Array(buf);
        for (var k = 0; k + 3 < u.length; k++) {
          if (u[k] === 0x01 && u[k+1] === 0x00 && u[k+2] === 0x00 && u[k+3] === 0xd4) {
            total++;
            if (samples.length < 10) {
              var roff = r.base.sub(mod.base).add(k);
              samples.push('mod+0x' + roff.toString(16));
            }
          }
        }
      } catch (e) {}
    });
    log('runtime svc#0 total=' + total + ' samples=' + samples.join(','));
  } catch (e) { log('range scan ERR ' + e); }

  try {
    rpc.exports = {
      init: function () { return Promise.resolve(); },
      status: function () { return 'done'; }
    };
  } catch (e) {}
})();
