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

    // ===== 文本搜索 =====
    // 老接口（H5/mock 场景；服务端已把未登录请求引导到登录墙）
    public static final String API_TEXT_SEARCH = "mtop.taobao.wsearch.appsearch";
    public static final String API_TEXT_SEARCH_VERSION = "1.0";
    public static final String API_TEXT_SUGGEST = "mtop.taobao.wsearch.suggest";
    // 真机 10.69.10 统一搜索页实际调用的接口（Frida hook buildParams 实测）：
    // mtop.relationrecommend.MtopRecommend.recommend v1.0，data 带
    // requestAlias=wsearch / isEnterSrpSearch=true / q=关键词 / appId=66 / n=每页数
    // ——这是未登录也能返回商品列表的接口，app 协议应走此接口。
    public static final String API_TEXT_SEARCH_NATIVE = "mtop.relationrecommend.MtopRecommend.recommend";
    public static final String API_TEXT_SEARCH_NATIVE_VERSION = "1.0";

    // ===== 图片搜索/拍立淘 (mtop.relationrecommend.PailitaoRecommend.recommend) =====
    public static final String API_IMAGE_SEARCH = "mtop.relationrecommend.PailitaoRecommend.recommend";
    public static final String API_IMAGE_SEARCH_VERSION = "1.0";

    // ===== 应用身份 =====
    // appKey 证据：smali com/taobao/tao/util/GetAppKeyFromSecurity.getAppKey(0) 直接返回
    public static final String APP_KEY = "21646297";
    public static final String APP_KEY_ALT = "12574478";       // H5 页面场景候选
    public static final String APP_VERSION = "10.68.0";        // smali MtopInitializer 上下文
    public static final String SG_SDK_VERSION = "6.8.261102";  // libsgmainso.version.so 原文
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
