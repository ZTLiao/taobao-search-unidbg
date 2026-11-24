# -*- coding: utf-8 -*-
"""IDA 深度分析：反编译所有调用 open/read/fopen/fread/dlopen/fstat 的函数，
以及 JNI_OnLoad / doCommandNative 相关导出函数，导出伪代码到目录。"""
import os, sys, json, time

SO = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(__file__), 'libsgmainso-6.8.260901.fixed.so')
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ida_cfs')
os.makedirs(OUT_DIR, exist_ok=True)

import idapro
import idaapi, idc, ida_bytes, ida_funcs, ida_nalt, idautils

print('[*] opening', SO, flush=True)
rc = idapro.open_database(SO, run_auto_analysis=True)
print('[*] open rc=%r' % rc, flush=True)
try:
    idaapi.auto_wait()
except Exception as e:
    print('[!] auto_wait', e, flush=True)

# hexrays
try:
    import ida_hexrays
    HEXRAYS = ida_hexrays.init_hexrays_plugin()
except Exception as e:
    HEXRAYS = False
    print('[!] hexrays unavailable:', e, flush=True)
print('[*] hexrays:', HEXRAYS, flush=True)

INTEREST_IMPORTS = ['open', '__open_2', 'openat', 'read', '__read_chk', 'pread',
                    'pread64', 'mmap', 'mmap64', 'fopen', 'fread', 'fstat', 'stat',
                    'lseek', 'lseek64', 'dlopen', 'getcwd', 'access']

# 1) 收集目标导入函数的地址（PLT）
imp_addrs = {}   # addr -> name
for idx in range(ida_nalt.get_import_module_qty()):
    def cb(ea, name, ordinal):
        if name and any(name.split('@')[0] == k for k in INTEREST_IMPORTS):
            imp_addrs[ea] = name
        return True
    ida_nalt.enum_import_names(idx, cb)
print('[*] target imports:', len(imp_addrs), flush=True)

# 2) 找所有引用这些 PLT 的函数
target_funcs = {}
for imp_ea, imp_name in imp_addrs.items():
    for xr in idautils.XrefsTo(imp_ea, 0):
        f = ida_funcs.get_func(xr.frm)
        if not f:
            continue
        fa = f.start_ea
        target_funcs.setdefault(fa, set()).add(imp_name)
print('[*] functions calling target imports:', len(target_funcs), flush=True)

# 3) 加上所有导出符号里带 JNI / doCommand / Java_ 的
for ea in idautils.Functions():
    name = idc.get_func_name(ea) or ''
    low = name.lower()
    if ('jni_onload' in low or 'docommand' in low or 'jniclibrary' in low
            or name.startswith('Java_')):
        target_funcs.setdefault(ea, set()).add('EXPORT:' + name)
print('[*] funcs total target (with exports):', len(target_funcs), flush=True)

# 4) 反编译并导出
def decompile(ea):
    if not HEXRAYS:
        return None
    try:
        cf = ida_hexrays.decompile(ea)
        if cf is None:
            return None
        return str(cf)
    except Exception as e:
        return '// decompile failed: %s' % e

manifest = []
for fa, imps in sorted(target_funcs.items()):
    name = idc.get_func_name(fa) or ('sub_%X' % fa)
    pseudo = decompile(fa)
    fn = '%s_%s.c' % (fa, ''.join(c for c in name if c.isalnum() or c in '._')[:40])
    path = os.path.join(OUT_DIR, fn)
    with open(path, 'w', encoding='utf-8') as f:
        f.write('// func %s @ %s\n' % (name, hex(fa)))
        f.write('// imports: %s\n\n' % ','.join(sorted(imps)))
        f.write(pseudo or '// no pseudocode')
    manifest.append({'ea': hex(fa), 'name': name, 'imports': sorted(imps),
                     'pseudo_len': len(pseudo or ''), 'file': fn})

with open(os.path.join(OUT_DIR, 'manifest.json'), 'w', encoding='utf-8') as f:
    json.dump(manifest, f, ensure_ascii=False, indent=1)
print('[*] wrote %d pseudocode files to %s' % (len(manifest), OUT_DIR), flush=True)

# 控制台摘要：只打印同时调用 open+read 或 dlopen 的可疑函数
print('\n===== suspicious funcs (open/fopen + read/fread, or dlopen) =====', flush=True)
for m in manifest:
    imps = set(m['imports'])
    has_open = any(x in imps for x in ('open', '__open_2', 'openat', 'fopen'))
    has_read = any(x in imps for x in ('read', '__read_chk', 'pread', 'pread64', 'fread'))
    has_dl = 'dlopen' in imps
    if (has_open and has_read) or has_dl:
        print('  %s %-30s open=%s read=%s dl=%s len=%d :: %s' % (
            m['ea'], m['name'][:30], has_open, has_read, has_dl,
            m['pseudo_len'], ','.join(m['imports'][:6])), flush=True)

idapro.close_database(SO)
print('[*] done', flush=True)
