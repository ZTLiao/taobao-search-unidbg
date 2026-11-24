# -*- coding: utf-8 -*-
"""用 IDA Pro (idalib headless) 静态分析 SG so，导出字符串/函数/交叉引用。

目标：定位 libsgmainso 读取 APK 签名（base.apk / yw_1222 / META-INF / CERT.RSA）
以及调用 libc open/read/mmap/pread 的 native 函数，为精准 native hook 提供地址。

用法:
  IDADIR="C:/Program Files/IDA Professional 9.1" py -3 tools/analysis/ida_scan.py <so路径>
"""
import os, sys, json, time

SO = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(__file__), 'libsgmainso-6.8.260901.fixed.so')
OUT_DIR = os.path.dirname(os.path.abspath(__file__))

import idapro
import idaapi
import idc
import ida_bytes
import ida_funcs
import ida_nalt
import idautils

try:
    _ida_ver = idc.get_inf_attr(idc.INF_APP_NAME)
except Exception:
    try:
        _ida_ver = idaapi.get_inf_structure().app_name
    except Exception:
        _ida_ver = 'unknown'
print('[*] IDA version:', _ida_ver, flush=True)
print('[*] opening:', SO, flush=True)
t0 = time.time()
rc = idapro.open_database(SO, run_auto_analysis=True)
print('[*] open_database rc=%r (%.1fs)' % (rc, time.time() - t0), flush=True)
try:
    idaapi.auto_wait()
except Exception as e:
    print('[!] auto_wait:', e, flush=True)
print('[*] analysis done (%.1fs)' % (time.time() - t0), flush=True)

KEYWORDS = ['base.apk', 'yw_1222', 'CERT.RSA', 'META-INF', '.RSA', '.SF',
            'AndroidManifest', 'open', 'openat', 'read', 'pread', 'mmap',
            'fstat', 'lseek', 'signature', 'Signature', 'sign', 'cert', ' Cert',
            'apk', 'APK', 'GET_SIGNATURES']

def sec_name(ea):
    try:
        return idaapi.get_segment_name(ea) or '?'
    except Exception:
        return '?'

# ---------- 1) 字符串清单（含关键字标注）----------
strings = []
for s in idautils.Strings():
    try:
        val = str(s)
    except Exception:
        continue
    if not val:
        continue
    hit = [k for k in KEYWORDS if k.lower() in val.lower()]
    strings.append({'ea': hex(s.ea), 'len': len(val), 'val': val[:300],
                    'kw': hit, 'seg': sec_name(s.ea)})
print('[*] strings total:', len(strings), flush=True)
kw_strings = [x for x in strings if x['kw']]
print('[*] keyword strings:', len(kw_strings), flush=True)

# ---------- 2) 导出函数 ----------
funcs = []
for ea in idautils.Functions():
    name = idc.get_func_name(ea) or ''
    try:
        f = ida_funcs.get_func(ea)
        size = (f.end_ea - f.start_ea) if f else 0
    except Exception:
        size = 0
    funcs.append({'ea': hex(ea), 'name': name, 'seg': sec_name(ea), 'size': size})
print('[*] functions total:', len(funcs), flush=True)

# ---------- 3) 对关键字字符串做交叉引用，找引用函数 ----------
xref_funcs = {}
for s in kw_strings:
    ea = int(s['ea'], 16)
    refs = []
    for xr in idautils.XrefsTo(ea, 0):
        f = ida_funcs.get_func(xr.frm)
        fname = idc.get_func_name(xr.frm) or ''
        refs.append({'from': hex(xr.frm), 'func': hex(f.start_ea) if f else None,
                     'funcname': fname, 'type': xr.type})
        if f:
            xref_funcs.setdefault(hex(f.start_ea), {'name': fname, 'strings': []})
            if s['val'] not in xref_funcs[hex(f.start_ea)]['strings']:
                xref_funcs[hex(f.start_ea)]['strings'].append(s['val'][:120])
    s['refs'] = refs[:20]
    s['refcount'] = len(refs)

# ---------- 4) 导入函数（external）----------
imports = []
for idx in range(ida_nalt.get_import_module_qty()):
    mod = ida_nalt.get_import_module_name(idx)
    def cb(ea, name, ordinal):
        imports.append({'ea': hex(ea), 'module': mod, 'name': name})
        return True
    ida_nalt.enum_import_names(idx, cb)

# ---------- 导出 JSON ----------
result = {
    'so': SO,
    'ida_version': _ida_ver,
    'strings_total': len(strings),
    'keyword_strings': kw_strings,
    'functions_total': len(funcs),
    'xref_functions': xref_funcs,
    'imports': imports,
}
out = os.path.join(OUT_DIR, 'ida_scan_result.json')
with open(out, 'w', encoding='utf-8') as f:
    json.dump(result, f, ensure_ascii=False, indent=1)
print('[*] wrote', out, flush=True)

# ---------- 控制台摘要 ----------
print('\n===== 关键字字符串 =====', flush=True)
for s in kw_strings[:80]:
    print('  %s seg=%s rc=%d kw=%s :: %s' % (
        s['ea'], s['seg'], s.get('refcount', 0), ','.join(s['kw']),
        s['val'][:90].replace('\n', '\\n')), flush=True)
print('\n===== 引用关键字字符串的函数 =====', flush=True)
for ea, info in xref_funcs.items():
    print('  %s %-40s <= %s' % (ea, info['name'][:40], ' | '.join(info['strings'][:3])), flush=True)
print('\n===== libc/文件相关导入 =====', flush=True)
for imp in imports:
    n = (imp['name'] or '').lower()
    if any(k in n for k in ('open', 'read', 'mmap', 'fstat', 'lseek', 'close', 'stat')):
        print('  %s %s' % (imp['module'], imp['name']), flush=True)

idapro.close_database(SO)
print('[*] done', flush=True)
