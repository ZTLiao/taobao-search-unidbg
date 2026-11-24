package com.taobao.search.sign;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * 真实 unidbg 签名后端：模拟 libsgmainso-6.8.261102（SecurityGuard）。
 *
 * 实测链路：JNI_OnLoad(RegisterNatives->JNICLibrary.doCommandNative)
 *   -> init 链 10102/10101/10103/10104
 *   -> 签名命令 70102 -> {x-sign, x-mini-wua, x-sgext, x-umt}
 *
 * 这些头按 App(MTOP RPC) 协议透传给网关；H5 协议仍由 H5MtopSigner 用 _m_h5_tk 计算 MD5 sign。
 */
@Component
@ConditionalOnBean(name = "taobaoVM")
public class UnidbgMtopSigner implements MtopSigner {

    private static final Logger log = LoggerFactory.getLogger(UnidbgMtopSigner.class);

    /**
     * 真机 umid 设备 token（与 HTTP 头 umt 同源）。
     * unidbg 内 SG 读不到本地 token 时 x-umt 会返回全零 24 位——这是最明显的
     * 「非真机」特征（服务端能直接从 x-umt 全零判定模拟环境）。此处用配置的
     * 真机 umt 覆盖 x-umt，使签名结果头与 HTTP umt 头一致。
     */
    @Value("${mtop.umt:}")
    private String deviceUmt;

    private volatile SecurityGuardEngine engine;

    private SecurityGuardEngine engine() {
        if (engine == null) {
            synchronized (this) {
                if (engine == null) {
                    engine = SecurityGuardEngine.getInstance(
                            SgPaths.soPath(),
                            SgPaths.officialApk(),
                            SgPaths.mainZipPath(),
                            SgPaths.totemPath(),
                            com.taobao.search.config.TaobaoConstants.APP_KEY,
                            com.taobao.search.config.TaobaoConstants.APP_VERSION,
                            false);
                }
            }
        }
        return engine;
    }

    @Override
    public String backend() {
        return "unidbg";
    }

    @Override
    public Map<String, String> sign(String api, String version, String appKey, long t, String data) {
        // 无上下文时退化为兼容模式（仅链路自检用，生产请走带 SignContext 的重载）
        return sign(api, version, appKey, t, data, null, null,
                new SignContext("", "", "", "", "", "", "27", "", ""));
    }

    @Override
    public Map<String, String> sign(String api, String version, String appKey, long t,
                                    String data, String token, String cookie, SignContext ctx) {
        SignContext c = ctx == null
                ? new SignContext("", "", "", "", "", "", "27", "", "") : ctx;
        Map<String, String> headers = engine().sign(api, version, data, "r_" + t, t, c);
        if (headers.isEmpty()) {
            throw new IllegalStateException("unidbg 70102 签名返回空，请查看探针日志");
        }
        Map<String, String> result = new HashMap<String, String>(headers);
        // 消除 x-umt 全零特征：SG 在无本地 token 时产出 0000...0000，
        // 用真机 umt 覆盖，保证 x-umt 头 == umt 头（真机二者同源）。
        if (deviceUmt != null && !deviceUmt.trim().isEmpty()) {
            String xUmt = result.get("x-umt");
            if (xUmt == null || xUmt.matches("0+")) {
                result.put("x-umt", deviceUmt.trim());
                log.debug("x-umt 全零已替换为真机 umt len={}", deviceUmt.trim().length());
            }
        }
        log.info("unidbg 签名完成 api={} utdid.len={} deviceId.len={} x-sign.len={} sgext.len={} wua.len={}",
                api, c.getUtdid().length(), c.getDeviceId().length(),
                result.getOrDefault("x-sign", "").length(),
                result.getOrDefault("x-sgext", "").length(),
                result.getOrDefault("x-mini-wua", "").length());
        return result;
    }
}
