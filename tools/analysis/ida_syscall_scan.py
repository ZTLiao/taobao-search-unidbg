# -*- coding: utf-8 -*-
"""IDA 扫描 libsgmainso 中所有 svc 指令，反查 x8=syscall number，定位 openat/read 等直接系统调用。

ARM64: svc #0 = 0xD4000001 (LE: 01 00 00 D4)。syscall 号放 x8：
  __NR_openat=56, __NR_open=8000056(实际用 openat), __NR_read=63,
  __NR_pread64=17, __NR_mmap=222, __NR_fstat=80, __NR_lseek=62, __NR_getdents64=61
"""
import os, sys, json

SO = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(__file__), 'libsgmainso-6.8.260901.fixed.so')
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ida_syscalls.json')

import idapro, idaapi, idc, ida_bytes, ida_funcs, idautils
import ida_ua
try:
    import ida_segment
except Exception:
    ida_segment = None

print('[*] open', SO, flush=True)
idapro.open_database(SO, run_auto_analysis=True)
try:
    idaapi.auto_wait()
except Exception as e:
    print('[!] auto_wait', e, flush=True)

# ARM64 syscall numbers (generic)
SYSCALLS = {
    56: 'openat', 57: 'close', 63: 'read', 64: 'write', 17: 'pread64',
    62: 'lseek', 80: 'fstat', 79: 'stat', 222: 'mmap', 61: 'getdents64',
    217: 'getcwd', 269: 'openat2',
}

svcs = []
# 遍历所有已定义指令，找 svc
for seg in idautils.Segments():
    if ida_segment:
        _s = ida_segment.getseg(seg)
        seg_ea = _s.start_ea
        end = _s.end_ea
    else:
        seg_ea = idc.get_seg_start(seg)
        end = idc.get_seg_end(seg)
    ea = seg_ea
    while ea < end:
        mnemonic = idc.print_insn_mnem(ea)
        if mnemonic and mnemonic.lower().startswith('svc'):
            # 向上回溯最多 20 条指令，找 mov x8, #imm 或 mov w8, #imm
            sc_num = None
            back = []
            cur = ea
            for _ in range(24):
                cur = ida_bytes.prev_head(cur, seg_ea)
                if cur == idaapi.BADADDR or cur < seg_ea:
                    break
                mn = idc.print_insn_mnem(cur) or ''
                op0 = idc.print_operand(cur, 0) or ''
                op1 = idc.print_operand(cur, 1) or ''
                back.append('%x: %s %s, %s' % (cur, mn, op0, op1))
                # mov x8, #imm / mov w8, #imm / movz/movk x8
                if op0 in ('X8', 'W8', 'x8', 'w8') and ('#' in op1):
                    try:
                        v = int(op1.replace('#', '').strip().replace('0x', ''), 16 if '0x' in op1 else 10)
                        sc_num = v
                        break
                    except Exception:
                        pass
            f = ida_funcs.get_func(ea)
            fname = idc.get_func_name(ea) or (('sub_%X' % f.start_ea) if f else '?')
            svcs.append({
                'svc_ea': hex(ea),
                'func': hex(f.start_ea) if f else None,
                'fname': fname,
                'syscall_num': sc_num,
                'syscall_name': SYSCALLS.get(sc_num, '?') if sc_num is not None else '?',
                'context': back[:12],
            })
        ea = ida_bytes.next_head(ea, end)

print('[*] total svc:', len(svcs), flush=True)
# 按 syscall 名聚合
from collections import Counter
c = Counter(s['syscall_name'] for s in svcs)
print('[*] syscall breakdown:', dict(c), flush=True)

with open(OUT, 'w', encoding='utf-8') as fp:
    json.dump(svcs, fp, ensure_ascii=False, indent=1)
print('[*] wrote', OUT, flush=True)

# 打印 openat/read/pread/mmap 相关
key = ('openat', 'openat2', 'read', 'pread64', 'mmap', 'getdents64', 'fstat')
for s in svcs:
    if s['syscall_name'] in key:
        print('\nSVC %s sc=%s(%s) func=%s %s' % (
            s['svc_ea'], s['syscall_num'], s['syscall_name'], s['func'], s['fname']), flush=True)
        for line in s['context'][:8]:
            print('   ', line, flush=True)

idapro.close_database(SO)
print('[*] done', flush=True)
