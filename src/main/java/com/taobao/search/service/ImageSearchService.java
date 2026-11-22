package com.taobao.search.service;

import com.taobao.search.config.TaobaoConstants;
import com.taobao.search.model.ApiResponse;
import com.taobao.search.model.ImageSearchRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 图片搜索（拍立淘）服务。
 *
 * 链路: TaoInit.initCapture -> CaptureActivity -> BitmapUtil.encodeBitmap(bmp,JPEG,70)
 *       -> tb.pft.c() -> ImageSearchMtopUtil.j -> mtop.relationrecommend.PailitaoRecommend.recommend
 *
 * 关键点（逆向所得）：图片不是 multipart 上传，而是 JPEG->base64 放进参数 strimg，
 * 随 MTOP 请求体一起 POST；上传+识别是同一个接口。
 */
@Service
public class ImageSearchService {

    private static final Logger log = LoggerFactory.getLogger(ImageSearchService.class);

    @Autowired
    private MtopHttpClient mtop;

    /** 允许读取的本地图片根目录，防止 imagePath 被用作任意文件读取。 */
    @Value("${image.allowed-dir:/tmp/tb_img}")
    private String allowedDir;

    public ApiResponse search(ImageSearchRequest req) {
        Map<String, Object> biz = buildParams(req);
        if (biz == null) {
            return ApiResponse.fail(TaobaoConstants.API_IMAGE_SEARCH, "local",
                    "需要提供 imageBase64 / imageUrl / imagePath 之一");
        }
        return mtop.call(TaobaoConstants.API_IMAGE_SEARCH,
                TaobaoConstants.API_IMAGE_SEARCH_VERSION,
                biz, req.getSignBackend(), req.isHuman(), req.getToken(), req.getCookie());
    }

    /** 复刻 ImageSearchMtopUtil.h() 的公共业务参数 */
    private Map<String, Object> buildParams(ImageSearchRequest req) {
        Map<String, Object> p = new LinkedHashMap<String, Object>();

        if (req.getImageBase64() != null && !req.getImageBase64().isEmpty()) {
            String b64 = stripDataPrefix(req.getImageBase64());
            p.put("strimg", b64);
            p.put("region", req.getRegion() != null ? req.getRegion() : "full");
        } else if (req.getImagePath() != null && !req.getImagePath().isEmpty()) {
            String b64 = encodeFile(req.getImagePath());
            if (b64 == null) return null;
            p.put("strimg", b64);
            p.put("region", req.getRegion() != null ? req.getRegion() : "full");
        } else if (req.getImageUrl() != null && !req.getImageUrl().isEmpty()) {
            p.put("searchimg", req.getImageUrl());
            p.put("region", req.getRegion() != null ? req.getRegion() : "0,0,0,0");
        } else {
            return null;
        }

        p.put("full_region_size", "full");
        p.put("biz_type", TaobaoConstants.PLT_BIZ_TYPE);
        p.put("subSearchType", TaobaoConstants.PLT_SUB_SEARCH_TYPE);
        p.put("m", TaobaoConstants.PLT_M);
        p.put("n", TaobaoConstants.PLT_N);
        p.put("appId", TaobaoConstants.PLT_APP_ID);
        p.put("_sid_", TaobaoConstants.PLT_SID);
        p.put("scene", TaobaoConstants.PLT_SCENE);
        p.put("page", 1);
        p.put("from", "");
        p.put("pssource", "sy");
        p.put("extraParams",
                "use_multi_cat:1;use_pid_summary:1;cat_deleted:1;use_pid_tag:1;extend_count:3");
        return p;
    }

    private String stripDataPrefix(String s) {
        int i = s.indexOf(',');
        if (s.startsWith("data:") && i > 0) return s.substring(i + 1);
        return s;
    }

    private String encodeFile(String path) {
        try {
            Path base = Paths.get(allowedDir).toRealPath();
            Path target = Paths.get(path).toRealPath();
            // 安全：真实路径必须位于白名单目录内，拒绝 ../ 与绝对路径越界（如 /etc/shadow）。
            if (!target.startsWith(base)) {
                log.warn("拒绝越界图片路径 path={} base={}", path, base);
                return null;
            }
            if (!Files.isRegularFile(target)) {
                log.warn("非普通文件，拒绝 path={}", path);
                return null;
            }
            long size = Files.size(target);
            if (size > 10L * 1024 * 1024) {
                log.warn("图片超过 10MB，拒绝 path={} size={}", path, size);
                return null;
            }
            byte[] bytes = Files.readAllBytes(target);
            return java.util.Base64.getEncoder().encodeToString(bytes);
        } catch (IOException e) {
            log.warn("读取图片失败 path={}: {}", path, e.toString());
            return null;
        }
    }
}
