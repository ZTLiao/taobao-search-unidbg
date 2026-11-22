package com.taobao.search.probe;

import com.taobao.search.config.TaobaoConstants;
import com.taobao.search.sign.SecurityGuardEngine;
import com.taobao.search.sign.SignContext;

import java.util.Map;

/**
 * 生产签名路径回归探针：直接调用 SecurityGuardEngine.sign(..., SignContext)，
 * 用真机 Frida hook 到的 ground truth 设备身份构造 22 段 INPUT，验证 native 70102 能正常出四头。
 *
 * 覆盖 E2E 的盲区：E2E 走 h5 mock 网关，不经过 native；此探针验证本轮
 * SignContext payload 修复后生产签名引擎依然可用。
 *
 * 用法（见 tools/regression.sh）：
 *   java -Djna.tmpdir=/tmp/unidbg-jna -cp <classes:test-classes:deps> \
 *        com.taobao.search.probe.SignEngineRegression
 */
public class SignEngineRegression {

    public static void main(String[] args) {
        String res = "src/main/resources/native";
        SecurityGuardEngine engine = SecurityGuardEngine.getInstance(
                res + "/arm64-v8a/libsgmainso-6.8.261102.so",
                "/Users/liaozetao/Projects/ReaProjects/app/com.taobao.taobao.apk",
                res + "/arm64-v8a/libsgmain.so",
                res + "/totem/yw_1222.jpg",
                TaobaoConstants.APP_KEY,
                TaobaoConstants.APP_VERSION,
                false);

        // 真机 10.69.10 Frida hook ground truth（见 HOOK_GUIDE.md 第 10 章）
        SignContext ctx = new SignContext(
                "awJISchpPiMDADAJ3weNXszG",                          // utdid 24
                "Aiw8S8YGCUMNCOMAFfPJIdq-Pyb4740VtErxvLS58KdE",      // deviceId 44
                "",                                                   // sid（未登录）
                "",                                                   // uid
                "231200@taobao_android_10.69.10",                    // ttid（真机格式）
                "openappkey=DEFAULT_AUTH",                            // extdata
                "27",                                                 // x-features
                "37.42195",                                           // lat
                "-122.084013");                                       // lng

        String api = "mtop.taobao.wsearch.appsearch";
        String version = "1.0";
        String data = "{\"q\":\"连衣裙\",\"page\":1}";
        long t = System.currentTimeMillis() / 1000;

        long t0 = System.currentTimeMillis();
        Map<String, String> headers = engine.sign(api, version, data, "r_regression_" + t, t, ctx);
        long cost = System.currentTimeMillis() - t0;

        System.out.println("\n[REGRESSION] sign cost=" + cost + "ms headers=" + headers);
        String[] required = {"x-sign", "x-mini-wua", "x-sgext", "x-umt"};
        boolean ok = true;
        for (String k : required) {
            String v = headers.get(k);
            boolean present = v != null && !v.isEmpty();
            System.out.println("[REGRESSION] " + k + " present=" + present
                    + (present ? " len=" + v.length() : " <<< MISSING"));
            ok &= present;
        }
        System.out.println("[REGRESSION] RESULT=" + (ok ? "PASS" : "FAIL"));
        if (!ok) System.exit(1);
    }
}
