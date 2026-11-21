package com.taobao.search.service;

import com.taobao.search.config.TaobaoConstants;
import com.taobao.search.model.ApiResponse;
import com.taobao.search.model.SearchRequest;
import org.springframework.beans.factory.annotation.Autowired;
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

    public ApiResponse search(SearchRequest req) {
        if (req.getQ() == null || req.getQ().trim().isEmpty()) {
            return ApiResponse.fail(TaobaoConstants.API_TEXT_SEARCH,
                    "local", "关键词 q 不能为空");
        }
        Map<String, Object> biz = new LinkedHashMap<String, Object>();
        biz.put("q", req.getQ());
        biz.put("page", req.getPage());
        biz.put("pageSize", req.getPageSize());
        biz.put("search_action", "search");
        biz.put("from", "searchdoor");
        biz.put("jarvisDisable", "false");

        return mtop.call(TaobaoConstants.API_TEXT_SEARCH,
                TaobaoConstants.API_TEXT_SEARCH_VERSION,
                biz, req.getSignBackend(), req.isHuman(), req.getToken(), req.getCookie());
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
