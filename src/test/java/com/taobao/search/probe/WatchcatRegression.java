package com.taobao.search.probe;

import com.taobao.search.model.ApiResponse;
import com.taobao.search.service.WatchcatFallbackClient;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

/**
 * 免登录静态兜底 CDN 回归探针。
 * 直接实例化 WatchcatFallbackClient（反射注入 @Value 默认值），验证：
 *   1) buildUrl 的 MD5 向量确定性（离线，不依赖网络）
 *   2) enabled=false 时返回 null 的回退契约（离线）
 *   3) 多关键词 / 多 page / 特殊字符关键词返回真实商品（在线）
 *
 * 运行：java -cp <classes:deps> com.taobao.search.probe.WatchcatRegression
 */
public class WatchcatRegression {
    private static final String CDN = "https://cdn-watchcat.s.taobao.com/watchcat-z-66/";

    public static void main(String[] args) throws Exception {
        WatchcatFallbackClient client = new WatchcatFallbackClient();
        setField(client, "enabled", true);
        setField(client, "timeoutMs", 15000);

        boolean allOk = true;

        // ===== 1) 离线：URL 构造确定性（与 2026-11-23 实测向量比对） =====
        System.out.println("===== [1] buildUrl MD5 确定性校验（离线） =====");
        String[][] vectors = {
                {"iphone18", "1", "3f3f58c767b9b9a59dafde2048cd36c2"},
                {"iphone",   "1", "228776fa638c7a15100e12439fe4be21"},
                {"连衣裙",   "1", "4109659f84f26fcc3b0e90639fc7a041"},
        };
        for (String[] v : vectors) {
            String url = client.buildUrl(v[0], Integer.parseInt(v[1]));
            String expect = CDN + v[2] + ".json";
            boolean ok = expect.equals(url);
            System.out.printf("  %-10s page=%s -> %s  %s%n",
                    v[0], v[1], ok ? "MATCH" : "MISMATCH", url);
            if (!ok) {
                System.out.println("     expected=" + expect);
                allOk = false;
            }
        }

        // ===== 2) 离线：enabled=false 必须返回 null（上层据此回退其它通道） =====
        System.out.println("\n===== [2] 回退契约校验（离线） =====");
        WatchcatFallbackClient disabled = new WatchcatFallbackClient();
        setField(disabled, "enabled", false);
        ApiResponse off = disabled.search("iphone", 1);
        boolean offOk = (off == null);
        System.out.println("  enabled=false -> " + (offOk ? "null (PASS)" : "non-null (FAIL)"));
        allOk &= offOk;

        // ===== 3) 在线：真实商品数据矩阵 =====
        System.out.println("\n===== [3] 在线真实商品矩阵 =====");
        // {关键词, page, 是否硬性要求返回真实商品}
        // 冷门/特殊字符词仅作信息性探测：CDN 是热门预置库，无数据属于合法行为，不算回归失败。
        String[][] cases = {
                {"iphone18",       "1", "1"},
                {"iphone18",       "2", "1"},
                {"iphone",         "1", "1"},
                {"连衣裙",         "1", "1"},
                {"iPhone 18 Pro",  "1", "0"},  // 带空格 + 大小写混合
                {"不存在的商品xyzzy", "1", "0"}, // 冷门词，信息性
        };
        for (String[] c : cases) {
            String q = c[0];
            int page = Integer.parseInt(c[1]);
            boolean required = "1".equals(c[2]);
            System.out.println("\n  ----- q=\"" + q + "\" page=" + page
                    + (required ? " [硬性]" : " [信息性]") + " -----");
            String url = client.buildUrl(q, page);
            System.out.println("  URL = " + url);

            ApiResponse r = client.search(q, page);
            if (r == null || !r.isSuccess()) {
                System.out.println("  RESULT = " + (required ? "FAIL (no data)" : "INFO (no data, 允许)"));
                if (required) allOk = false;
                continue;
            }

            List<Map<String, Object>> items = r.getItems();
            Object total = r.getRawData() == null ? null : r.getRawData().get("totalResults");
            System.out.printf("  ret=%s backend=%s items=%d total=%s%n",
                    r.getRet(), r.getSignBackend(), items == null ? 0 : items.size(), str(total));

            int shown = 0;
            if (items != null) {
                for (Map<String, Object> it : items) {
                    if (shown++ >= 3) break;
                    System.out.println(String.format("    - %s | ¥%s | %s",
                            str(it.get("title")), str(it.get("price")), str(it.get("itemId"))));
                }
            }

            boolean hasTitle = items != null && !items.isEmpty()
                    && items.get(0).get("title") != null
                    && !String.valueOf(items.get(0).get("title")).trim().isEmpty();
            boolean backendOk = "watchcat-static-cdn".equals(r.getSignBackend());
            boolean urlOk = url.equals(r.getRequestUrl());
            boolean pass = hasTitle && backendOk && urlOk;
            System.out.println("  RESULT = " + (pass ? "PASS (真实商品)"
                    : "FAIL (title=" + hasTitle + " backend=" + backendOk + " url=" + urlOk + ")"));
            if (required && !pass) allOk = false;
        }

        System.out.println("\n========== WATCHCAT_REGRESSION=" + (allOk ? "PASS" : "FAIL") + " ==========");
        if (!allOk) System.exit(1);
    }

    static void setField(Object obj, String name, Object val) throws Exception {
        Field f = obj.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(obj, val);
    }

    static String str(Object o) { return o == null ? "" : String.valueOf(o); }
}
