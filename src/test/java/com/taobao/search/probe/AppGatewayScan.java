package com.taobao.search.probe;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.taobao.search.sign.SecurityGuardEngine;
import com.taobao.search.sign.SignContext;
import com.taobao.search.sign.SgPaths;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.GZIPInputStream;

/**
 * App 网关接口扫描：用真实 unidbg 70102 产出 native 四头，打真实 acs /gw/，
 * 逐层验证协议门槛（m-* 头族）与业务/风控层，找出免登录下能出真实数据的接口。
 *
 * 重要（HOOK_GUIDE §15，2026-11-22 实测决定性结论）：
 *   - m-pv/m-appkey/m-sign/m-t 是网关对「我们请求形态」强制索要的协议门槛，
 *     与 x-sign 真伪无关；构造头族即可过，无需逆 m-sign 算法。
 *   - m-t 必须是【当前秒级时间戳】；写死 "1" -> FAIL_SYS_ACCESS_DENIED / REQUEST_EXPIRED。
 *   - m-sign 内容不敏感（非空即可）。
 *
 * 本探针修正点（相对旧版）：
 *   1) m-t 从写死 "1" 改为真实 t —— 这是旧版卡在 ACCESS_DENIED 的唯一根因。
 *   2) 搜索主接口从废弃的 mtop.taobao.wsearch.appsearch 换成真机 ground truth
 *      mtop.relationrecommend.MtopRecommend.recommend + requestAlias=wsearch 完整 data（§11.2）。
 *   3) 图片接口 data 用真机外层封装 {"params":"{...}","appId":"32969"}（§17.1）。
 *   4) 抓取完整风控响应头（bx-action/bx-retry/bxpunish/Location）用于分层诊断。
 *
 * 用法（见 tools/scan_app_gateway.sh）：
 *   java -Djna.tmpdir=/tmp/unidbg-jna -cp <classes:test-classes:deps> \
 *        com.taobao.search.probe.AppGatewayScan
 */
public class AppGatewayScan {

    static final String GW = "https://acs.m.taobao.com/gw/";
    static final String APP_KEY = "21646297";
    static final String APP_VER = "10.69.10";
    static final String UA = "MTOPSDK/3.1.1.7 (Android;13;Google;sdk_gphone64_arm64) DeviceType(Phone)";
    static final String TTID = "231200@taobao_android_10.69.10";
    static final String UTDID = "awJISchpPiMDADAJ3weNXszG";
    static final String DEVICE_ID = "Aiw8S8YGCUMNCOMAFfPJIdq-Pyb4740VtErxvLS58KdE";
    static final String UMT = "qDAB/NZLPNRUEgKiASBAdlHAivDtXDIF";

    static final String API_SUGGEST = "mtop.taobao.wsearch.suggest";
    static final String API_TEXT = "mtop.relationrecommend.MtopRecommend.recommend";
    static final String API_IMAGE = "mtop.relationrecommend.PailitaoRecommend.recommend";

    static SecurityGuardEngine engine;
    static SignContext ctx;

    public static void main(String[] args) throws Exception {
        engine = SecurityGuardEngine.getInstance(
                SgPaths.soPath(), SgPaths.officialApk(), SgPaths.mainZipPath(), SgPaths.totemPath(),
                APP_KEY, APP_VER, false);
        ctx = new SignContext(UTDID, DEVICE_ID, "", "", TTID,
                "openappkey=DEFAULT_AUTH", "27", "37.42195", "-122.084013");

        System.out.println("\n========== App 网关真实数据扫描（unidbg 四头 + m-* 协议头族）==========");

        // 1) 协议门槛对照：suggest 无 m-* 头（预期 PROTOVER_MISSED）
        probe("联想词 suggest（无 m 头）", API_SUGGEST, suggestData(), false);
        // 2) 协议门槛对照：suggest 有 m-* 头 + 正确 m-t（预期穿越协议层 -> USER_VALIDATE 或 SUCCESS）
        probe("联想词 suggest（m 头 + 真实 m-t）", API_SUGGEST, suggestData(), true);
        // 3) 文本搜索真机主接口 + 真机 data（§11.2）
        probe("文本搜索 MtopRecommend（m 头）", API_TEXT, textData("iphone18"), true);
        // 4) 图片搜索真机主接口 + 外层封装 data（§17.1）
        probe("图片搜索 PailitaoRecommend（m 头）", API_IMAGE, imageData(), true);

        System.out.println("========== 扫描结束 ==========");
    }

    static String suggestData() {
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        m.put("q", "iphone18");
        m.put("area", "active_page");
        m.put("src", "c2c");
        m.put("history", "off");
        return JSON.toJSONString(m);
    }

    /** 真机 10.69.10 统一搜索页 data 结构（HOOK_GUIDE §11.2 原样复刻） */
    static String textData(String q) {
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        m.put("active_bd", "1");
        m.put("appId", "66");
        m.put("areaCode", "CN");
        m.put("brand", "google");
        m.put("bxFeature", "{\"TT\":1,\"data\":[],\"error_code\":20807,\"fetchTime\":0}");
        m.put("isEnterSrpSearch", "true");
        m.put("n", "10");
        m.put("page", "1");
        m.put("q", q);
        m.put("requestAlias", "wsearch");
        m.put("style", "list");
        m.put("ttid", TTID);
        m.put("utd_id", UTDID);
        m.put("vm", "nw");
        return JSON.toJSONString(m);
    }

    /** 真机图片搜索 data 外层封装（HOOK_GUIDE §17.1，平铺结构会 ILEGEL_SIGN） */
    static String imageData() {
        Map<String, Object> inner = new LinkedHashMap<String, Object>();
        inner.put("biz_type", "pai");
        inner.put("subSearchType", "imageText_v3");
        inner.put("appId", "32969");
        inner.put("page", 1);
        // 用一个极短占位图片签名探测（仅验证签名层是否认可 data 封装；真实图片回归走正式服务）
        inner.put("strimg", "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRof");
        inner.put("region", "full");
        Map<String, Object> outer = new LinkedHashMap<String, Object>();
        outer.put("params", JSON.toJSONString(inner));
        outer.put("appId", "32969");
        return JSON.toJSONString(outer);
    }

    static void probe(String label, String api, String data, boolean mHeaders) throws Exception {
        long t = System.currentTimeMillis() / 1000;
        Map<String, String> sign = engine.sign(api, "1.0", data, "r_scan_" + t + "_" + api.hashCode(), t, ctx);
        String xSign = get(sign, "x-sign");
        String xWua = get(sign, "x-mini-wua");
        String xSgext = get(sign, "x-sgext");
        String xUmt = get(sign, "x-umt");

        Map<String, String> form = new LinkedHashMap<String, String>();
        form.put("jsv", "2.7.2");
        form.put("appKey", APP_KEY);
        form.put("t", String.valueOf(t));
        form.put("sign", xSign);
        form.put("api", api);
        form.put("v", "1.0");
        form.put("type", "json");
        form.put("dataType", "json");
        form.put("ttid", TTID);
        form.put("data", data);
        form.put("utdid", UTDID);
        form.put("deviceId", DEVICE_ID);
        form.put("sid", "");
        form.put("uid", "");
        form.put("umt", UMT);
        form.put("extdata", "openappkey=DEFAULT_AUTH");
        form.put("x-features", "27");

        Map<String, String> h = new LinkedHashMap<String, String>();
        h.put("User-Agent", UA);
        h.put("Content-Type", "application/x-www-form-urlencoded");
        h.put("x-t", String.valueOf(t));
        h.put("x-app-ver", APP_VER);
        h.put("x-features", "27");
        h.put("x-ttid", TTID);
        h.put("x-sign", xSign);
        h.put("x-umt", xUmt);
        h.put("x-mini-wua", xWua);
        h.put("x-sgext", xSgext);
        h.put("x-utdid", UTDID);
        h.put("x-devid", DEVICE_ID);
        h.put("umt", UMT);
        // 注意：禁止 x-pv（实测必触发 PROTOPARAM_MISSED）
        if (mHeaders) {
            h.put("m-pv", "8.1.0");
            h.put("m-appkey", APP_KEY);
            h.put("m-sign", xSign);       // 内容不敏感，非空即可（§15.2）
            h.put("m-t", String.valueOf(t)); // ★关键：当前秒级时间戳，非写死 "1"
        }

        String body = encode(form);
        HttpURLConnection conn = (HttpURLConnection) new URL(GW + api + "/1.0/").openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(20000);
        conn.setInstanceFollowRedirects(false);
        for (Map.Entry<String, String> e : h.entrySet()) conn.setRequestProperty(e.getKey(), e.getValue());
        OutputStream os = conn.getOutputStream();
        os.write(body.getBytes(StandardCharsets.UTF_8));
        os.close();

        int code = conn.getResponseCode();
        InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
        String resp = is == null ? "" : readAll(is);
        String bx = conn.getHeaderField("bxpunish");
        String bxAction = conn.getHeaderField("bx-action");
        String bxRetry = conn.getHeaderField("bx-retry");
        String location = conn.getHeaderField("Location");
        if (location != null && location.length() > 120) location = location.substring(0, 120) + "...";
        conn.disconnect();

        String ret;
        String dataPreview;
        try {
            JSONObject j = JSON.parseObject(resp);
            ret = String.valueOf(j.get("ret"));
            Object d = j.get("data");
            dataPreview = d == null ? "null" : String.valueOf(d);
            if (dataPreview.length() > 240) dataPreview = dataPreview.substring(0, 240) + "...";
        } catch (Exception e) {
            ret = resp.length() > 120 ? resp.substring(0, 120) : resp;
            dataPreview = "";
        }
        boolean real = ret.contains("SUCCESS");
        System.out.println("[" + (real ? "★真实数据★ " : "") + label + "] HTTP " + code
                + " ret=" + ret);
        System.out.println("      风控: bxpunish=" + bx + " bx-action=" + bxAction
                + " bx-retry=" + bxRetry + (location != null ? " Location=" + location : ""));
        System.out.println("      sign: x-sign.len=" + xSign.length() + " x-wua.len=" + xWua.length()
                + " x-sgext.len=" + xSgext.length() + " x-umt.len=" + xUmt.length());
        if (real) System.out.println("      data=" + dataPreview);
    }

    static String get(Map<String, String> m, String k) {
        String v = m.get(k);
        return v == null ? "" : v;
    }

    static String encode(Map<String, String> p) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : p.entrySet()) {
            if (sb.length() > 0) sb.append('&');
            try {
                sb.append(URLEncoder.encode(e.getKey(), "UTF-8")).append('=')
                  .append(URLEncoder.encode(String.valueOf(e.getValue()), "UTF-8"));
            } catch (Exception ex) { }
        }
        return sb.toString();
    }

    static String readAll(InputStream is) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
        return new String(bos.toByteArray(), StandardCharsets.UTF_8);
    }
}
