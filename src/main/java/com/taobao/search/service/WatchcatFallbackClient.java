package com.taobao.search.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.taobao.search.model.ApiResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.HostnameVerifier;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 淘宝搜索「静态兜底 CDN」免登录数据源。
 *
 * 逆向来源（淘宝 10.69.0 smali，证据见 HOOK_GUIDE §21）：
 *   tb/b54.smali:337-427 —— 搜索请求失败时的兜底逻辑：
 *     key  = "66_30.4" + q + page
 *     hash = MD5(key) 小写十六进制（tb/e4p.a → b[MD5] → d[hex]）
 *     url  = "https://cdn-watchcat.s.taobao.com/watchcat-z-66/" + hash + ".json"
 *
 * 关键价值：这是纯静态 CDN，不需要签名 / 设备指纹 / Cookie / 登录态，
 * 也不经过 bixi 风控，直接返回真实商品 JSON（totalResults / itemsArray）。
 * 已实测：iphone18 返回 Apple/苹果 iPhone 18 Pro ¥9999，与真机 UI 截图一致。
 *
 * 这是目前唯一稳定、免登录、可返回真实商品数据的文本搜索通道。
 */
@Component
public class WatchcatFallbackClient {

    private static final Logger log = LoggerFactory.getLogger(WatchcatFallbackClient.class);

    private static final String CDN = "https://cdn-watchcat.s.taobao.com/watchcat-z-66/";
    private static final String PREFIX = "66_30.4";

    @Value("${search.watchcat.enabled:true}")
    private boolean enabled;

    @Value("${search.watchcat.timeout-ms:15000}")
    private int timeoutMs;

    /** 是否启用兜底 CDN（供上层判断） */
    public boolean isEnabled() { return enabled; }

    /** 构造兜底 CDN URL（公开便于测试） */
    public String buildUrl(String q, int page) {
        String key = PREFIX + q + page;
        String hash = md5(key);
        return CDN + hash + ".json";
    }

    /**
     * 走静态兜底 CDN 搜索，成功返回 ApiResponse(success=true)，失败返回 null 让上层回退其它通道。
     */
    public ApiResponse search(String q, int page) {
        if (!enabled) return null;
        String url = buildUrl(q, page);
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            // 该 CDN 是公开只读静态数据，无凭据。部分环境有 MITM 代理 CA 不在 JDK trust store，
            // 仅对此连接放宽证书校验（不影响项目其它 HTTPS 调用）。
            if (conn instanceof HttpsURLConnection) {
                applyTrustAll((HttpsURLConnection) conn);
            }
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestProperty("User-Agent",
                    "Mozilla/5.0 (Linux; Android 13; Pixel) AppleWebKit/537.36");
            int code = conn.getResponseCode();
            InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
            if (is == null) { conn.disconnect(); return null; }
            String body = readAll(is);
            conn.disconnect();
            if (code != 200 || body.isEmpty()) {
                log.warn("[watchcat] HTTP {} empty={} url={}", code, body.isEmpty(), url);
                return null;
            }

            JSONObject jo = JSON.parseObject(body);
            if (jo == null) return null;
            JSONArray arr = jo.getJSONArray("itemsArray");
            List<Map<String, Object>> items = new ArrayList<Map<String, Object>>();
            if (arr != null) {
                for (int i = 0; i < arr.size(); i++) {
                    Object o = arr.get(i);
                    if (o instanceof JSONObject) items.add(normalize((JSONObject) o));
                }
            }
            if (items.isEmpty()) {
                log.warn("[watchcat] no items q={} page={}", q, page);
                return null;
            }

            Map<String, Object> raw = new LinkedHashMap<String, Object>();
            raw.put("totalResults", jo.get("totalResults"));
            raw.put("totalPage", jo.get("totalPage"));
            raw.put("pageSize", jo.get("pageSize"));
            raw.put("page", jo.get("page"));
            raw.put("itemsArray", items);

            log.info("[watchcat] q={} page={} items={} total={} url={}",
                    q, page, items.size(), jo.get("totalResults"), url);
            ApiResponse r = ApiResponse.ok(
                    "watchcat-fallback", "SUCCESS::静态兜底CDN（免登录）",
                    "watchcat-static-cdn", url, raw, items);
            return r.withDiagnostics("SUCCESS", "none", 1,
                    "免登录静态兜底CDN，无需签名/设备指纹/Cookie；真实商品来自淘宝 watchcat 预置数据",
                    null, signMeta(q, page, url));
        } catch (Exception e) {
            log.warn("[watchcat] error q={} page={} url={} : {}", q, page, url, e.toString());
            return null;
        }
    }

    /** 把商品 JSON 归一化为统一字段，便于上层展示 */
    @SuppressWarnings("unchecked")
    private Map<String, Object> normalize(JSONObject o) {
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        String title = firstNonBlank(o, "title", "short_title", "short_title_c2c");
        String price = firstNonBlank(o, "price", "localPrice");
        String pic = firstNonBlank(o, "pic_path", "picPath", "imageUrl");
        String itemId = firstNonBlank(o, "uniqpid", "itemId", "nid");
        if (pic.isEmpty()) {
            JSONArray info = o.getJSONArray("imageInfo");
            if (info != null && !info.isEmpty() && info.get(0) instanceof JSONObject) {
                pic = firstNonBlank((JSONObject) info.get(0), "imageUrl");
            }
        }
        m.put("title", title);
        m.put("price", price);
        m.put("picUrl", pic);
        m.put("itemId", itemId);
        m.put("auctionURL", str(o.get("auctionURL")));
        m.put("raw", o);
        return m;
    }

    private String firstNonBlank(JSONObject o, String... keys) {
        for (String k : keys) {
            Object v = o.get(k);
            if (v != null && !String.valueOf(v).trim().isEmpty()) return String.valueOf(v);
        }
        return "";
    }

    private String str(Object v) { return v == null ? "" : String.valueOf(v); }

    private Map<String, String> signMeta(String q, int page, String url) {
        Map<String, String> m = new LinkedHashMap<String, String>();
        m.put("_watchcat", "enabled");
        m.put("_watchcat_key", PREFIX + q + page);
        m.put("_watchcat_url", url);
        return m;
    }

    /** 仅对静态兜底 CDN 连接放宽证书校验（公开只读数据，环境可能有 MITM 代理 CA） */
    private static void applyTrustAll(HttpsURLConnection conn) throws Exception {
        TrustManager[] tm = new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tm, new SecureRandom());
        conn.setSSLSocketFactory(ctx.getSocketFactory());
        HostnameVerifier all = (host, session) -> true;
        conn.setHostnameVerifier(all);
    }

    private String md5(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] bytes = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("MD5 unavailable", e);
        }
    }

    private String readAll(InputStream is) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
        return new String(bos.toByteArray(), StandardCharsets.UTF_8);
    }
}
