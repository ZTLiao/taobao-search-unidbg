#!/usr/bin/env python3
"""生成 rpc_sign_bundle.js：复用 hook_full_bundle.js 里已打包的 frida-java-bridge 运行时。

Frida 17 不再内置 Java bridge，直接 -l rpc_sign.js 会报 Java is not defined。
本脚本把 hook_full_bundle.js 的 bridge 初始化段（到 require_agent(); 为止）
与 rpc_sign.js 拼接，产出可独立加载的 bundle。

用法: python3 tools/frida/build_rpc_bundle.py
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.join(HERE, 'hook_full_bundle.js')
SRC = os.path.join(HERE, 'rpc_sign.js')
OUT = os.path.join(HERE, 'rpc_sign_bundle.js')

MARK = '  require_agent();'


def build(src_path, out_path, label):
    with open(BASE, encoding='utf-8') as f:
        base_lines = f.read().splitlines(True)
    prefix = []
    found = False
    for line in base_lines:
        prefix.append(line)
        if line.rstrip('\n') == MARK:
            found = True
            break
    if not found:
        raise SystemExit('未找到 bridge 入口标记: %r' % MARK)

    with open(src_path, encoding='utf-8') as f:
        src = f.read()

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(''.join(prefix))
        # 原文件在末尾才闭合入口 IIFE，这里提前闭合，避免带入原 hook 逻辑
        f.write('})();\n')
        f.write('\n// ===== %s（由 build_rpc_bundle.py 拼接）=====\n' % label)
        f.write(src)

    print('written %s (%d bytes)' % (out_path, os.path.getsize(out_path)))


def main():
    build(SRC, OUT, '真机签名 RPC')
    # 精简版：只提供 nativeSearch，不装任何诊断 hook（gadget 进程内模式必用，避免 JNI 崩溃）
    native_src = os.path.join(HERE, 'rpc_native_only.js')
    native_out = os.path.join(HERE, 'rpc_native_only_bundle.js')
    if os.path.exists(native_src):
        build(native_src, native_out, '精简原生搜索 RPC')
    # 安全捕获版：只做值拷贝的 buildParams hook，抓真机搜索 ground truth
    cap_src = os.path.join(HERE, 'rpc_capture_safe.js')
    cap_out = os.path.join(HERE, 'rpc_capture_safe_bundle.js')
    if os.path.exists(cap_src):
        build(cap_src, cap_out, '安全签名捕获 RPC')
    # 只 hook n9f.r 的值拷贝版（buildParams hook 在 gadget 模式会 SIGABRT）
    n9f_src = os.path.join(HERE, 'rpc_n9f_capture.js')
    n9f_out = os.path.join(HERE, 'rpc_n9f_capture_bundle.js')
    if os.path.exists(n9f_src):
        build(n9f_src, n9f_out, 'n9f 签名捕获 RPC')
    # Mtop 上下文诊断：纯主动调用，无 hook
    probe_src = os.path.join(HERE, 'rpc_probe_mtop.js')
    probe_out = os.path.join(HERE, 'rpc_probe_mtop_bundle.js')
    if os.path.exists(probe_src):
        build(probe_src, probe_out, 'Mtop 上下文诊断 RPC')
    # 统一诊断：probe + nativeSearch，纯主动调用（推荐 gadget 模式）
    diag_src = os.path.join(HERE, 'rpc_native_diag.js')
    diag_out = os.path.join(HERE, 'rpc_native_diag_bundle.js')
    if os.path.exists(diag_src):
        build(diag_src, diag_out, '原生搜索+诊断 RPC')
    # 主线程版 nativeSearch（验证 SecException 1927 是否线程上下文问题）
    mt_src = os.path.join(HERE, 'rpc_main_thread.js')
    mt_out = os.path.join(HERE, 'rpc_main_thread_bundle.js')
    if os.path.exists(mt_src):
        build(mt_src, mt_out, '主线程原生搜索 RPC')


if __name__ == '__main__':
    main()
