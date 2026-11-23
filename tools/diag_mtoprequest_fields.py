#!/usr/bin/env python3
"""枚举 tb/w4j 请求上下文里 MtopRequest 的全部字段，用于安全 clone。

只读诊断：不改任何对象字段，避免 JNI 引用失效崩溃。
"""
import os

import frida

host = os.environ.get('FRIDA_GADGET_HOST', '127.0.0.1')
port = os.environ.get('FRIDA_GADGET_PORT', '27043')
addr = '%s:%s' % (host, port)

JS = r"""
function dumpFields(obj, label) {
  var out = [];
  try {
    var cls = obj.getClass();
    var fields = cls.getDeclaredFields();
    for (var i = 0; i < fields.length; i++) {
      var f = fields[i];
      try {
        f.setAccessible(true);
        var v = f.get(obj);
        var vs = v === null ? 'null' : (typeof v === 'object' ? String(v.getClass().getName()) : String(v));
        var val = v === null ? '' : (vs.indexOf('String') >= 0 ? String(v) : '');
        out.push(f.getName() + ' : ' + vs + (val ? ' = ' + val.substring(0,80) : ''));
      } catch (e) { out.push(f.getName() + ' : <err ' + e + '>'); }
    }
  } catch (e) { out.push(label + ' ERR ' + e); }
  return out;
}

rpc.exports.inspect = function () {
  var res = {w4jFound:0, reqFields:[], ctxFields:[], mtopInfo:{}};
  Java.perform(function () {
    Java.choose('tb/w4j', {
      onMatch: function (inst) {
        if (res.w4jFound >= 1) return 'stop';
        res.w4jFound++;
        res.ctxFields = dumpFields(inst, 'w4j');
        try {
          var req = inst.b.value;
          if (req) { res.reqFields = dumpFields(req, 'MtopRequest'); res.reqClass = String(req.getClass().getName()); }
        } catch (e) { res.reqErr = String(e); }
      },
      onComplete: function () {}
    });
  });
  return JSON.stringify(res);
};
"""

print('[diag] connecting', addr)
dev = frida.get_device_manager().add_remote_device(addr)
session = dev.attach('Gadget')
script = session.create_script(JS)
script.on('message', lambda m, d: print('[msg]', m))
script.load()
print('[diag] loaded, call inspect()')
r = script.exports_sync.inspect()
import json
print(json.dumps(json.loads(r), ensure_ascii=False, indent=2)[:8000])
# 注意：不 unload、不 detach 后立即退出可能留下 hook；此脚本无 hook，安全
session.detach()
