package com.taobao.search.config;

import org.springframework.stereotype.Component;

/**
 * 从 taobao-rebuild 的 smali 逆向出的链路常量。
 * 证据见 docs/CHAIN_ANALYSIS.md。
 */
@Component
public class TaobaoConstants {

    // ===== MTOP 网关 =====
    public static final String MTOP_GATEWAY = "https://h5api.m.taobao.com/h5/";
    public static final String MTOP_GATEWAY_WAP = "https://h5.m.taobao.com/h5/";

    // ===== 文本搜索 (mtop.taobao.wsearch.appsearch) =====
    public static final String API_TEXT_SEARCH = "mtop.taobao.wsearch.appsearch";
    public static final String API_TEXT_SEARCH_VERSION = "1.0";
    public static final String API_TEXT_SUGGEST = "mtop.taobao.wsearch.suggest";

    // ===== 图片搜索/拍立淘 (mtop.relationrecommend.PailitaoRecommend.recommend) =====
    public static final String API_IMAGE_SEARCH = "mtop.relationrecommend.PailitaoRecommend.recommend";
    public static final String API_IMAGE_SEARCH_VERSION = "1.0";

    // ===== 应用身份 =====
    // 这类数字 appKey 在 mtopsdk 里普遍存在；实际以真机抓包为准，可用配置文件覆盖。
    public static final String APP_KEY = "12574478";           // 淘宝 H5 常用 appKey
    public static final String APP_KEY_ALT = "99807463";       // smali 中出现频次较高的候选
    public static final String TTID = "taobao@android_10.28.0";
    public static final String API_TYPE_JSON = "json";

    // ===== 拍立淘业务参数 (ImageSearchMtopUtil.h / tb.pft 逆向所得) =====
    public static final String PLT_BIZ_TYPE = "pai";
    public static final String PLT_SUB_SEARCH_TYPE = "imageText_v3";
    public static final String PLT_M = "api4etao";
    public static final String PLT_N = "60";
    public static final String PLT_APP_ID = "32969";
    public static final String PLT_SID = "69148";
    public static final String PLT_SCENE = "multiObject";

    // ===== 签名 / token 握手相关 =====
    public static final String SIGN_FIELD = "mtop_sign";
    public static final String SIGN_XFIELD = "x-sign";

    /** app 侧网关（native x-sign 走这里），H5 侧走 MTOP_GATEWAY */
    public static final String MTOP_GATEWAY_ACS = "https://acs.m.taobao.com/gw/";

    /** H5 标准握手 token Cookie 名；值形如 <token>_<毫秒时间戳> */
    public static final String COOKIE_H5_TK = "_m_h5_tk";
    public static final String COOKIE_H5_TK_ENC = "_m_h5_tk_enc";

    /** 网关返回码（用于诊断分类） */
    public static final String RET_TOKEN_EXPIRED = "FAIL_SYS_TOKEN_EXPIRED";
    public static final String RET_TOKEN_EMPTY = "FAIL_SYS_TOKEN_EMPTY";
    public static final String RET_RGV587 = "RGV587_ERROR";

    /**
     * H5 标准签名算法（公开协议）:
     *   sign = MD5(token & t & appKey & data)
     * token 由网关在首次请求通过 Set-Cookie: _m_h5_tk=<token>_<ts> 动态下发，
     * 无法从 APK 静态提取。实现见 H5MtopSigner / MtopTokenManager。
     */
    public static final String H5_SIGN_ALGORITHM = "MD5(token&t&appKey&data)";
}
