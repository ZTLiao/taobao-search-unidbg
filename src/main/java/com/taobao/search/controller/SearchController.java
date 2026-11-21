package com.taobao.search.controller;

import com.taobao.search.model.ApiResponse;
import com.taobao.search.model.ImageSearchRequest;
import com.taobao.search.model.SearchRequest;
import com.taobao.search.service.ImageSearchService;
import com.taobao.search.service.TextSearchService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** 对外 HTTP API */
@RestController
@RequestMapping("/api")
public class SearchController {

    @Autowired
    private TextSearchService textSearch;

    @Autowired
    private ImageSearchService imageSearch;

    /** 文本搜索: POST /api/search  {"q":"连衣裙","page":1} */
    @PostMapping("/search")
    public ApiResponse search(@RequestBody SearchRequest req) {
        return textSearch.search(req);
    }

    /** 搜索联想: GET /api/suggest?q=连衣裙 */
    @GetMapping("/suggest")
    public ApiResponse suggest(@RequestParam String q,
                               @RequestParam(required = false) String signBackend,
                               @RequestParam(defaultValue = "true") boolean human,
                               @RequestParam(required = false) String token,
                               @RequestParam(required = false) String cookie) {
        return textSearch.suggest(q, signBackend, human, token, cookie);
    }

    /** 图片搜索: POST /api/image_search  {"imageBase64":"..."} 或 {"imageUrl":"..."} */
    @PostMapping("/image_search")
    public ApiResponse imageSearch(@RequestBody ImageSearchRequest req) {
        return imageSearch.search(req);
    }

    /** 本地图片路径快捷接口: POST /api/image_search/path  {"imagePath":"/path/to.jpg"} */
    @PostMapping("/image_search/path")
    public ApiResponse imageSearchByPath(@RequestBody ImageSearchRequest req) {
        return imageSearch.search(req);
    }
}
