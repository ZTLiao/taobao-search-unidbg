package com.taobao.search.sign;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 签名后端路由：h5 / rpc / unidbg / mock。
 * 按配置或单次请求选择，任一后端异常可按 search.sign-fallback 降级到 mock。
 *
 *   h5      - 标准 H5 token 握手 + MD5 sign（自动获取有效 token，协议层可打通）
 *   rpc     - 转发到用户自建的 unidbg-server / 真机签名服务（app 私有 x-sign 来源）
 *   unidbg  - 本地补环境模拟 libsgmain（需 HOOK_GUIDE 补齐 JNI）
 *   mock    - 离线确定性占位，用于联调 / 降级
 */
@Component
public class SignerRouter {

    @Value("${search.sign-backend:h5}")
    private String defaultBackend;

    @Value("${search.sign-fallback:true}")
    private boolean fallback;

    @Autowired
    private MockMtopSigner mockSigner;

    @Autowired
    private H5MtopSigner h5Signer;

    @Autowired
    private RpcMtopSigner rpcSigner;

    @Autowired(required = false)
    private UnidbgMtopSigner unidbgSigner;

    public Map<String, String> sign(String api, String version, String appKey, long t,
                                    String data, String requestedBackend) {
        return sign(api, version, appKey, t, data, requestedBackend, null, null);
    }

    public Map<String, String> sign(String api, String version, String appKey, long t,
                                    String data, String requestedBackend,
                                    String token, String cookie) {
        return sign(api, version, appKey, t, data, requestedBackend, token, cookie, null);
    }

    public Map<String, String> sign(String api, String version, String appKey, long t,
                                    String data, String requestedBackend,
                                    String token, String cookie, SignContext ctx) {
        String b = normalize(requestedBackend);
        try {
            switch (b) {
                case "h5":
                    return h5Signer.sign(api, version, appKey, t, data, token, cookie, ctx);
                case "rpc":
                    return rpcSigner.sign(api, version, appKey, t, data, token, cookie, ctx);
                case "unidbg": {
                    if (unidbgSigner == null) {
                        throw new IllegalStateException("unidbg 后端未启用 (unidbg.enabled=false)");
                    }
                    // 联合签名：
                    //   1) unidbg(真实 libsgmainso) 产出真机四头 x-sign/x-mini-wua/x-sgext/x-umt
                    //   2) 叠加 H5 MD5 sign（token 有效时）——过 H5 网关校验
                    // 两者协议不同源：native x-sign 是 App 网关协议，H5 sign 是 query 校验
                    Map<String, String> nativeHeaders = unidbgSigner.sign(api, version, appKey, t, data, token, cookie, ctx);
                    try {
                        Map<String, String> h5 = h5Signer.sign(api, version, appKey, t, data, token, cookie);
                        String md5 = h5.get("sign");
                        if (md5 != null && !md5.isEmpty()) nativeHeaders.put("sign", md5);
                        nativeHeaders.put("_h5_sign", "present");
                    } catch (Exception e) {
                        nativeHeaders.put("_h5_sign", "absent: " + e.getMessage());
                    }
                    nativeHeaders.put("_native_headers", String.valueOf(nativeHeaders.size()));
                    return nativeHeaders;
                }
                case "mock":
                default:
                    return mockSigner.sign(api, version, appKey, t, data, token, cookie);
            }
        } catch (Exception e) {
            if (!fallback) {
                throw (e instanceof RuntimeException) ? (RuntimeException) e : new RuntimeException(e);
            }
            Map<String, String> r = mockSigner.sign(api, version, appKey, t, data, token, cookie);
            r.put("_fallback_reason", e.getMessage());
            r.put("_fallback_from", b);
            return r;
        }
    }

    public String backendName(String requested) {
        return normalize(requested);
    }

    /** h5 / unidbg 后端依赖 token 握手（MD5 sign 需要 token），需触发「拿 token → 重算 sign → 重试」闭环 */
    public boolean needsToken(String requested) {
        String b = normalize(requested);
        return "h5".equals(b) || "unidbg".equals(b);
    }

    public List<String> availableBackends() {
        List<String> l = new ArrayList<String>();
        l.add("h5");
        l.add("rpc");
        // unidbg 仅在 taobaoVM bean 就绪（unidbg.enabled=true）时实际可用；
        // 否则请求会被 fallback 降级到 mock，如实反映避免 health 误导。
        if (unidbgSigner != null) {
            l.add("unidbg");
        }
        l.add("mock");
        return l;
    }

    private String normalize(String b) {
        String x = (b == null || b.trim().isEmpty()) ? defaultBackend : b.trim();
        x = x.toLowerCase(Locale.ROOT);
        return ("h5".equals(x) || "rpc".equals(x) || "unidbg".equals(x) || "mock".equals(x))
                ? x : "mock";
    }
}
