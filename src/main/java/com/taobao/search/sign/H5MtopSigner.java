package com.taobao.search.sign;

import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

/**
 * MTOP H5 标准签名后端（真实公开算法）。
 *
 * sign = MD5(token &amp; t &amp; appKey &amp; data)
 *   token 来自网关下发的 _m_h5_tk（见 MtopTokenManager）。
 * 首次握手阶段 token 为空，此时 sign 用空 token 计算，网关会返回
 * FAIL_SYS_TOKEN_EXPIRED 并下发 token，客户端重算后带 Cookie 重试即通过。
 *
 * 这是 H5 网关的标准签名，能自动获取有效 token；它不是 app 私有 native x-sign
 * （后者由 libsgmain 生成，需真机 / unidbg 签名服务，见 RpcMtopSigner / UnidbgMtopSigner）。
 */
@Component
public class H5MtopSigner implements MtopSigner {

    @Override
    public String backend() { return "h5"; }

    @Override
    public Map<String, String> sign(String api, String version, String appKey, long t, String data) {
        return sign(api, version, appKey, t, data, null, null);
    }

    @Override
    public Map<String, String> sign(String api, String version, String appKey, long t,
                                    String data, String token, String cookie) {
        String tk = token == null ? "" : token;
        String sign = md5(tk + "&" + t + "&" + appKey + "&" + data);
        Map<String, String> r = new HashMap<String, String>();
        r.put("sign", sign);
        r.put("_h5_sign", "true");
        r.put("_token_used", tk.isEmpty() ? "empty(handshake)" : "present");
        return r;
    }

    /** 标准 MD5，供签名与本地 mock 网关共用同一算法定义 */
    public static String md5(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] b = md.digest(s.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte x : b) sb.append(String.format("%02x", x & 0xff));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
