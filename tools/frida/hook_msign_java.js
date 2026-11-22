/*
 * Hook 淘宝 mtopsdk 签名（Java 层，参数清晰），抓 m-sign / x-sign 生成链路 ground truth。
 *
 * 目标方法（10.68.0 / tb.n9f = mtopsdk.security.InnerSignImpl）：
 *   - getMtopApiSign(HashMap, String, String)         -> 老协议 sign
 *   - getUnifiedSign / a(HashMap,String,boolean)      -> 统一签名（x-sign 四头）
 *   - getSecurityFactors(HashMap)                      -> 安全因子（含 INPUT data 串）
 *   - doCommandNative(int, Object[])                   -> native 70102 兜底
 *
 * 用法：
 *   frida -U -f com.taobao.taobao -l tools/frida/hook_msign_java.js --no-pause
 * 或 attach 后手动触发一次搜索请求。
 */

'use strict';

function dumpMap(label, map) {
    try {
        if (map === null || map === undefined) { console.log(label + ' = null'); return; }
        var keys = map.keySet().toArray();
        var out = [];
        for (var i = 0; i < keys.length; i++) {
            var k = keys[i];
            var v = map.get(k);
            out.push(String(k) + '=' + (v === null ? 'null' : String(v)));
        }
        console.log(label + ' = {' + out.join(', ') + '}');
    } catch (e) {
        console.log(label + ' dumpMap ERR ' + e);
    }
}

Java.perform(function () {
    console.log('\n===== hook_msign_java loaded =====');

    // 1) InnerSignImpl.getMtopApiSign —— 老协议 sign
    try {
        var InnerSign = Java.use('mtopsdk.security.InnerSignImpl');
        var methods = InnerSign.class.getDeclaredMethods();
        console.log('[InnerSignImpl] methods:');
        methods.forEach(function (m) { console.log('   ' + m.toString()); });

        // getMtopApiSign 重载：HashMap, String, String
        var overloads = InnerSign.getMtopApiSign.overloads;
        overloads.forEach(function (ov) {
            ov.implementation = function () {
                console.log('\n>>> getMtopApiSign args=' + arguments.length);
                for (var i = 0; i < arguments.length; i++) {
                    var a = arguments[i];
                    if (a !== null && a.getClass && a.getClass().getName().indexOf('HashMap') >= 0) {
                        dumpMap('   arg[' + i + ']', a);
                    } else {
                        console.log('   arg[' + i + '] = ' + a);
                    }
                }
                var ret = ov.apply(this, arguments);
                console.log('<<< getMtopApiSign ret = ' + ret);
                return ret;
            };
        });
    } catch (e) {
        console.log('[InnerSignImpl] hook fail: ' + e);
    }

    // 2) JNICLibrary.doCommandNative —— native 70102 兜底（antuuid 链路）
    try {
        var JNIC = Java.use('com.taobao.wireless.security.adapter.JNICLibrary');
        JNIC.doCommandNative.implementation = function (cmd, args) {
            // 只打印签名相关命令，避免刷屏
            if (cmd === 70102 || cmd === 70101 || cmd === 70103) {
                console.log('\n>>> doCommandNative cmd=' + cmd);
                if (args !== null) {
                    try {
                        var n = args.length;
                        console.log('   args.length=' + n);
                        for (var i = 0; i < n && i < 12; i++) {
                            console.log('   arg[' + i + '] = ' + args[i]);
                        }
                    } catch (e) { console.log('   args dump err ' + e); }
                }
                var ret = this.doCommandNative(cmd, args);
                console.log('<<< doCommandNative(' + cmd + ') ret = ' + ret);
                return ret;
            }
            return this.doCommandNative(cmd, args);
        };
        console.log('[doCommandNative] hooked');
    } catch (e) {
        console.log('[doCommandNative] hook fail: ' + e);
    }

    // 3) 主动调用：拿 Mtop 实例的 sign 对象，用真机环境签一个测试串
    //    这是拿到「真机 x-sign 输出」最直接的方式，用于对照 unidbg 输出
    try {
        var Globals = Java.use('com.taobao.tao.Globals');
        var Mtop = Java.use('mtopsdk.mtop.intf.Mtop');
        console.log('[active] Globals/Mtop 可用，可按需补充主动调用逻辑');
    } catch (e) {
        console.log('[active] Globals/Mtop 不可用: ' + e);
    }

    console.log('===== hook ready，现在触发一次搜索请求 =====\n');
});
