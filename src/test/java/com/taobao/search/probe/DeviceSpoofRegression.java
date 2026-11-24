package com.taobao.search.probe;

import com.taobao.search.sign.SignContext;
import com.taobao.search.sign.UnidbgMtopSigner;

import java.lang.reflect.Field;
import java.util.Map;

/**
 * 设备态伪装回归：验证 UnidbgMtopSigner 消除 unidbg/模拟器特征。
 *
 * 校验点：
 *   1) x-umt 全零被替换为配置的真机 umt（x-umt 与 umt 头同源）
 *   2) native 四头仍完整产出
 *
 * 运行：java -cp <classes:test-classes:deps> com.taobao.search.probe.DeviceSpoofRegression
 */
public class DeviceSpoofRegression {
    static final String REAL_UMT = "nQkBd8pLPL4NaAKiAeNTMq1rozOWT26L";
    static final String UTDID = "awJ3hY/Mq3EDAMWt0Bs6MAqV";
    static final String DEVICE_ID = "AuBCx84bur5HR28RMM72yrJz4vwoHvSvwGKrf56_wj6j";
    static final String TTID = "231200@taobao_android_10.69.10";

    public static void main(String[] args) throws Exception {
        UnidbgMtopSigner signer = new UnidbgMtopSigner();
        // 反射注入 @Value（脱离 Spring 上下文单测）
        Field f = UnidbgMtopSigner.class.getDeclaredField("deviceUmt");
        f.setAccessible(true);
        f.set(signer, REAL_UMT);

        SignContext ctx = new SignContext(UTDID, DEVICE_ID, "", "", TTID,
                "openappkey=DEFAULT_AUTH", "27", "37.42195", "-122.084013");

        String data = "{\"requestAlias\":\"wsearch\",\"q\":\"iphone18\",\"page\":\"1\"}";
        long t = System.currentTimeMillis() / 1000;
        Map<String, String> h = signer.sign(
                "mtop.relationrecommend.MtopRecommend.recommend", "1.0",
                "21646297", t, data, "", "", ctx);

        boolean allOk = true;
        String xUmt = h.get("x-umt");
        boolean umtOk = REAL_UMT.equals(xUmt);
        System.out.println("[1] x-umt 替换: " + (umtOk ? "PASS" : "FAIL")
                + " x-umt=" + xUmt);
        allOk &= umtOk;

        String[] need = {"x-sign", "x-mini-wua", "x-sgext", "x-umt"};
        for (String k : need) {
            String v = h.get(k);
            boolean ok = v != null && !v.isEmpty() && !v.matches("0+");
            System.out.println("    " + k + ": " + (ok ? "OK" : "FAIL")
                    + " len=" + (v == null ? 0 : v.length()));
            allOk &= ok;
        }

        System.out.println("\n========== DEVICE_SPOOF_REGRESSION="
                + (allOk ? "PASS" : "FAIL") + " ==========");
        if (!allOk) System.exit(1);
    }
}
