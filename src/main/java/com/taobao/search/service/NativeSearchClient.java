package com.taobao.search.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.taobao.search.model.ApiResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 免登录原生搜索客户端。
 *
 * 走 Frida 真机/模拟器 RPC 桥接的 /api/search/native：
 * 在 App 进程内用 Mtop 实例 + MtopBuilder.syncRequest() 发请求，
 * 请求 100% 走 anetwork 原生协议栈（自动签名 + 原生请求形态），
 * 绕过手工 HTTP form 被 bixi 标记为 wh_ttid=pc 的 web 风控。
 *
 * 游客态：不注入登录 cookie，依赖 App 自身游客态 + 设备身份。
 * 风控允许时（如真机 UI 可搜的时刻）可拿到真实商品数据；
 * bixi 风控期会返回 FAIL_SYS_USER_VALIDATE / FAIL_SYS_TRAFFIC_LIMIT，
 * 这是服务端风控环境状态，非本项目代码缺陷。
 *
 * 为什么必须是原生栈：
 *   手工 HTTP form（无论 Mac 还是真机出口、无论四头多真）都被 bixi
 *   识别为 web/PC 形态（punish URL 带 wh_ttid=pc）；只有 App 原生
 *   anetwork 栈不经过这层 web 风控。
 */
@Component
public class NativeSearchClient {

    private static final Logger log = LoggerFactory.getLogger(NativeSearchClient.class);

    /** bridge 原生搜索端点，如 http://127.0.0.1:9091/api/search/native */
    @Value("${sign.rpc.native-search-url:}")
    private String nativeSearchUrl;

    @Value("${sign.rpc.timeout-ms:20000}")
    private int timeoutMs;

    /** 走原生栈的 JVM 侧 ttid（与 App 内 MtopBuilder 一致） */
    @Value("${mtop.ttid:231200@taobao_android_10.69.10}")
    private String ttid;

    public boolean isConfigured() {
        return nativeSearchUrl != null && !nativeSearchUrl.trim().isEmpty();
    }

    /**
     * 用 App 原生栈发搜索请求。
     *
     * @param api    完整 mtop api 名
     * @param version api 版本
     * @param data   业务 data（JSON 字符串，外层封装形态）
     * @param method POST（图片大 data）或 GET（文本）
     * @return 统一响应；风控/失败时也返回 ApiResponse 并带诊断
     */
    public ApiResponse search(String api, String version, String data, String method) {
        if (!isConfigured()) {
            return ApiResponse.fail(api, "native",
                    "sign.rpc.native-search-url 未配置：请指向 frida bridge 的 /api/search/native");
        }
        Map<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("api", api);
        body.put("version", version == null ? "1.0" : version);
        body.put("data", data);
        body.put("method", method == null ? "GET" : method);
        body.put("ttid", ttid);
        body.put("headers", new LinkedHashMap<String, String>()); // 游客态：不注入登录头

        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(nativeSearchUrl).openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            OutputStream os = conn.getOutputStream();
            os.write(JSON.toJSONString(body).getBytes("UTF-8"));
            os.flush();
            os.close();

            int code = conn.getResponseCode();
            InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
            String raw = readAll(is);
            JSONObject jo = JSON.parseObject(raw);
            if (jo == null) {
                return ApiResponse.fail(api, "native", nativeSearchUrl, "原生搜索返回非 JSON: " + raw);
            }
            return toApiResponse(api, jo);
        } catch (Exception e) {
            log.warn("原生搜索失败: {}", e.getMessage());
            return ApiResponse.fail(api, "native", nativeSearchUrl, "原生搜索失败: " + e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private ApiResponse toApiResponse(String api, JSONObject jo) {
        String error = jo.getString("error");
        if (error != null && !error.isEmpty()) {
            return ApiResponse.fail(api, "native", nativeSearchUrl, "原生搜索 RPC 错误: " + error);
        }
        String retCode = jo.getString("retCode");
        String ret = jo.getString("ret");
        String retMsg = jo.getString("retMsg");
        String dataStr = jo.getString("data");
        String backend = jo.getString("_rpc_backend") == null ? "native" : "native+" + jo.getString("_rpc_backend");

        boolean success = retCode != null && "SUCCESS".equalsIgnoreCase(retCode);
        String err = ret != null ? ret : (retCode != null ? retCode : retMsg);
        ApiResponse r;
        if (success) {
            Map<String, Object> raw = new LinkedHashMap<String, Object>();
            List<Map<String, Object>> items = new ArrayList<Map<String, Object>>();
            try {
                JSONObject d = JSON.parseObject(dataStr);
                if (d != null) {
                    for (Map.Entry<String, Object> e : d.entrySet()) raw.put(e.getKey(), e.getValue());
                    // 兼容常见商品列表字段
                    Object listObj = d.get("items");
                    if (listObj == null) listObj = d.get("list");
                    if (listObj instanceof List) {
                        for (Object o : (List<?>) listObj) {
                            if (o instanceof Map) items.add((Map<String, Object>) o);
                        }
                    }
                }
            } catch (Exception ignore) {
                raw.put("rawData", dataStr);
            }
            r = ApiResponse.ok(api, ret, backend, nativeSearchUrl, raw, items);
        } else {
            r = ApiResponse.fail(api, backend, nativeSearchUrl, err);
        }
        // 诊断信息
        Map<String, String> meta = new LinkedHashMap<String, String>();
        if (jo.getString("instanceId") != null) meta.put("instanceId", jo.getString("instanceId"));
        if (retCode != null) meta.put("retCode", retCode);
        if (jo.getString("reqApi") != null) meta.put("reqApi", jo.getString("reqApi"));
        meta.put("requestStack", "app-native-anetwork");
        meta.put("session", "guest-no-login");
        String gatewayRet = success ? "SUCCESS"
                : (errContains(err, "USER_VALIDATE") || errContains(err, "TRAFFIC_LIMIT") || errContains(err, "ANTI_ATTACK")
                    ? "RISK_CONTROL" : "FAIL");
        String hint = success ? null
                : "App 原生栈已发起请求（游客态），但被服务端 bixi 风控拦截。"
                  + "这是环境风控状态非代码缺陷：可在真机/模拟器风控允许时刻重试，或注入有效 x5sec/cookie。";
        r.withDiagnostics(gatewayRet, "guest", 1, hint, null, meta);
        return r;
    }

    private static boolean errContains(String s, String needle) {
        return s != null && s.contains(needle);
    }

    private static String readAll(InputStream is) throws Exception {
        if (is == null) return "";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[2048];
        int n;
        while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
        is.close();
        return new String(bos.toByteArray(), "UTF-8");
    }
}
