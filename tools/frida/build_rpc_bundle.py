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


def main():
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

    with open(SRC, encoding='utf-8') as f:
        src = f.read()

    with open(OUT, 'w', encoding='utf-8') as f:
        f.write(''.join(prefix))
        # 原文件在末尾才闭合入口 IIFE，这里提前闭合，避免带入原 hook 逻辑
        f.write('})();\n')
        f.write('\n// ===== 真机签名 RPC（由 build_rpc_bundle.py 拼接）=====\n')
        f.write(src)

    print('written %s (%d bytes)' % (OUT, os.path.getsize(OUT)))


if __name__ == '__main__':
    main()
