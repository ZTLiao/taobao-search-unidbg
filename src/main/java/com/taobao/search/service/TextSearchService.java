package com.taobao.search.service;

import com.taobao.search.config.TaobaoConstants;
import com.alibaba.fastjson.JSON;
import com.taobao.search.model.ApiResponse;
import com.taobao.search.model.SearchRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 文本搜索服务。
 * 链路: SearchBarWidget -> SearchDoorWidget -> SearchActivity
 *       -> CommonBaseDatasource -> mtop.taobao.wsearch.appsearch
 */
@Service
public class TextSearchService {

    @Autowired
    private MtopHttpClient mtop;

    @Autowired
    private HumanBehaviorSimulator human;

    @Autowired(required = false)
    private NativeSearchClient nativeSearch;

    @Autowired(required = false)
    private WatchcatFallbackClient watchcat;

    /** 协议模式：watchcat=静态兜底CDN（免登录首选）；native=App 原生栈免登录；app=真机 data 结构手工 form；h5=标准网关 */
    @Value("${mtop.protocol:h5}")
    private String protocol;

    public ApiResponse search(SearchRequest req) {
        if (req.getQ() == null || req.getQ().trim().isEmpty()) {
            return ApiResponse.fail(TaobaoConstants.API_TEXT_SEARCH,
                    "local", "关键词 q 不能为空");
        }

        // watchcat 静态兜底 CDN：唯一稳定、免登录、无需签名/设备指纹的真实数据通道。
        // 逆向来源 tb/b54.smali（HOOK_GUIDE §21）。失败时回退到其它协议栈。
        if ("watchcat".equalsIgnoreCase(protocol) && watchcat != null && watchcat.isEnabled()) {
            ApiResponse r = watchcat.search(req.getQ().trim(), req.getPage());
            if (r != null && r.isSuccess()) return r;
        }

        boolean nativeMode = "native".equalsIgnoreCase(protocol);
        boolean appMode = "app".equalsIgnoreCase(protocol) || nativeMode;
        String api = appMode ? TaobaoConstants.API_TEXT_SEARCH_NATIVE : TaobaoConstants.API_TEXT_SEARCH;
        String version = appMode ? TaobaoConstants.API_TEXT_SEARCH_NATIVE_VERSION
                : TaobaoConstants.API_TEXT_SEARCH_VERSION;

        Map<String, Object> biz = appMode
                ? nativeSearchData(req)
                : legacySearchData(req);

        if (nativeMode && nativeSearch != null && nativeSearch.isConfigured()) {
            // 原生栈 + 游客态：data 用真机完整结构（含 bxFeature），GET 避免超长
            return nativeSearch.search(api, version, JSON.toJSONString(biz), "GET");
        }
        return mtop.call(api, version, biz, req.getSignBackend(), req.isHuman(),
                req.getToken(), req.getCookie());
    }

    /**
     * 真机 10.69.10 统一搜索页 data 结构（Frida hook buildParams 实测原样复刻）。
     * 关键区分字段：requestAlias=wsearch / isEnterSrpSearch=true / appId=66 / q=关键词。
     */
    private Map<String, Object> nativeSearchData(SearchRequest req) {
        Map<String, Object> biz = new LinkedHashMap<String, Object>();
        biz.put("active_bd", "1");
        biz.put("appId", "66");
        biz.put("areaCode", "CN");
        biz.put("brand", "google");
        biz.put("bxFeature", "{\"TT\":1,\"data\":[],\"error_code\":20807,\"fetchTime\":0}");
        biz.put("canP4pVideoPlay", "false");
        biz.put("client_os", "Android");
        biz.put("client_os_version", "35");
        biz.put("countryNum", "156");
        biz.put("device", "sdk_gphone64_arm64");
        biz.put("elderHome", "false");
        biz.put("enablePicShot", "true");
        biz.put("gpsEnabled", "false");
        biz.put("grayHair", "false");
        biz.put("hasPreposeFilter", "false");
        biz.put("info", "gprs");
        biz.put("isBeta", "false");
        biz.put("isEnterSrpSearch", "true");
        biz.put("n", String.valueOf(req.getPageSize()));
        biz.put("needTabs", "true");
        biz.put("network", "3g");
        biz.put("newSortBar", "true");
        biz.put("nsNative", "true");
        biz.put("page", String.valueOf(req.getPage()));
        biz.put("style", "list");
        biz.put("q", req.getQ());
        biz.put("rainbow", "5484,5866,5690,4991,5838,5609");
        biz.put("requestAlias", "wsearch");
        biz.put("searchElderHomeOpen", "false");
        biz.put("sversion", "30.5");
        biz.put("tb2025", "true");
        biz.put("ttid", resolveTtid());
        biz.put("utd_id", human.sessionUtdid());
        biz.put("vm", "nw");
        return biz;
    }

    /** 从 MtopHttpClient 的 ttid 配置读取（保持与 form 参数 / 签名 INPUT 一致） */
    @Value("${mtop.ttid:" + TaobaoConstants.TTID + "}")
    private String ttid;

    private String resolveTtid() { return human != null ? human.effectiveTtid(ttid) : ttid; }

    /** 老接口 data 结构（H5/mock 场景，保持不变） */
    private Map<String, Object> legacySearchData(SearchRequest req) {
        Map<String, Object> biz = new LinkedHashMap<String, Object>();
        biz.put("q", req.getQ());
        biz.put("page", req.getPage());
        biz.put("pageSize", req.getPageSize());
        biz.put("search_action", "search");
        biz.put("from", "searchdoor");
        biz.put("jarvisDisable", "false");
        return biz;
    }

    /** 搜索联想词: mtop.taobao.wsearch.suggest */
    public ApiResponse suggest(String q, String backend, boolean human) {
        return suggest(q, backend, human, null, null);
    }

    public ApiResponse suggest(String q, String backend, boolean human,
                               String token, String cookie) {
        Map<String, Object> biz = new LinkedHashMap<String, Object>();
        biz.put("q", q);
        biz.put("area", "active_page");
        biz.put("src", "c2c");
        biz.put("history", "off");
        return mtop.call(TaobaoConstants.API_TEXT_SUGGEST, "1.0", biz,
                backend, human, token, cookie);
    }
}
