package com.taobao.search.sign;

import java.util.Map;

/**
 * 可插拔签名后端接口。
 * 对应 smali 链路: mtopsdk.security.InnerSignImpl (tb/n9f) -> ISecureSignatureComponent.signRequest。
 *
 * 约定返回 Map：
 *   - "sign"      : H5 网关 query 参数 sign
 *   - "x-*"       : 作为 HTTP header 下发（x-sign / x-sgext / x-mini-wua 等）
 *   - "mtop_sign" : app 侧签名占位（兼容旧实现）
 *   - "_*"        : 元信息/诊断，不会下发到网关
 */
public interface MtopSigner {
    /** 后端标识: h5 / rpc / unidbg / mock */
    String backend();

    /** 基础签名（不依赖 token）。mock / unidbg 用此实现。 */
    Map<String, String> sign(String api, String version, String appKey, long t, String data);

    /**
     * 带 token/cookie 的签名。H5 标准握手需要 token 参与 MD5。
     * 默认忽略 token，委托到基础签名；需要 token 的后端覆盖此方法。
     */
    default Map<String, String> sign(String api, String version, String appKey, long t,
                                     String data, String token, String cookie) {
        return sign(api, version, appKey, t, data);
    }

    /**
     * 带完整设备上下文的签名（native x-sign 用）。
     * 默认忽略 ctx，委托到带 token 的签名；只有 unidbg / rpc 后端需要真实设备三要素。
     */
    default Map<String, String> sign(String api, String version, String appKey, long t,
                                     String data, String token, String cookie, SignContext ctx) {
        return sign(api, version, appKey, t, data, token, cookie);
    }
}
