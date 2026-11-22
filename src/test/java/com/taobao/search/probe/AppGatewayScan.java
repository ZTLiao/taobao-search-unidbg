package com.taobao.search.probe;

import com.taobao.search.config.TaobaoConstants;
import com.taobao.search.sign.SecurityGuardEngine;
import com.taobao.search.sign.SignContext;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.GZIPInputStream;

/**
 * App 网关接口扫描：用真实 unidbg 70102 签名，批量测试多个 App 接口，
 * 找出哪些接口在「无登录态」下能返回真实数据（SUCCESS + data）。
 *
 * 背景：搜索主接口 mtop.taobao.wsearch.appsearch 强制登录验证（FAIL_SYS_USER_VALIDATE），
 * 但联想词 / 热门词 / 首页推荐等轻量接口通常不要求登录。
 *
 * 用法（见 tools/scan_app_gateway.sh）：
 *   java -Djna.tmpdir=/tmp/unidbg-jna -cp <classes:test-classes:deps> \
 *        com.taobao.search.probe.AppGatewayScan
 */
public class AppGatewayScan {

    static final String GW = "https://acs.m.taobao.com/gw/";
    static final String APP_KEY = "21646297";
    static final String UA = "MTOPSDK/3.1.1.7 (Android;10;Xiaomi;MI 9)";
    static final String TTID = "231200@taobao_android_10.69.10";
    static final String UTDID = "awJISchpPiMDADAJ3weNXszG";
    static final String DEVICE_ID = "Aiw8S8YGCUMNCOMAFfPJIdq-Pyb4740VtErxvLS58KdE";

    static SecurityGuardEngine engine;
    static SignContext ctx;

    public static void main(String[] args) {
        String res = "src/main/resources/native";
        engine = SecurityGuardEngine.getInstance(
                res + "/arm64-v8a/libsgmainso-6.8.261102.so",
                "/Users/liaozetao/Projects/ReaProjects/app/com.taobao.taobao.apk",
                res + "/arm64-v8a/libsgmain.so",
                res + "/totem/yw_1222.jpg",
                APP_KEY, "10.68.0", false);
        ctx = new SignContext(UTDID, DEVICE_ID, "", "", TTID,
                "openappkey=DEFAULT_AUTH", "27", "37.42195", "-122.084013");

        // {label, api, data, 是否加 m-* 头}
        String[][] cases = {
                {"联想词 suggest",        "mtop.taobao.wsearch.suggest",            "{\"q\":\"iphone18\"}", "0"},
                {"热门词 hotsuggest",     "mtop.taobao.wsearch.hotsuggest",        "{}", "0"},
                {"猜你想搜 guess",        "mtop.taobao.wsearch.guess",             "{}", "0"},
                {"首页推荐 awesome.get",  "mtop.taobao.wireless.home.newface.awesome.get", "{\"pageId\":\"home\"}", "0"},
                {"搜索主接口 appsearch",  "mtop.taobao.wsearch.appsearch",         "{\"q\":\"iphone18\",\"page\":1,\"pageSize\":10}", "0"},
                {" suggest + m头",        "mtop.taobao.wsearch.suggest",           "{\"q\":\"iphone18\"}", "1"},
                {"appsearch + m头",       "mtop.taobao.wsearch.appsearch",         "{\"q\":\"iphone18\",\"page\":1,\"pageSize\":10}", "1"},
        };

        System.out.println("\n========== App 网关真实数据扫描 ==========");
        for (String[] c : cases) {
            try {
                probe(c[0], c[1], c[2], "1".equals(c[3]));
            } catch (Exception e) {
                System.out.println("[" + c[0] + "] EXCEPTION " + e);
            }
        }
        System.out.println("========== 扫描结束 ==========");
    }

    static void probe(String label, String api, String data, boolean mHeaders) throws Exception {
        long t = System.currentTimeMillis() / 1000;
        Map<String, String> sign = engine.sign(api, "1.0", data, "r_scan_" + t, t, ctx);
        String xSign = get(sign, "x-sign");
        String xWua = get(sign, "x-mini-wua");
        String xSgext = get(sign, "x-sgext");
        String xUmt = get(sign, "x-umt");

        // form body（app 协议：参数全在 body，无 query）
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
        form.put("uid", "");
        form.put("sid", "");

        Map<String, String> h = new LinkedHashMap<String, String>();
        h.put("User-Agent", UA);
        h.put("Content-Type", "application/x-www-form-urlencoded");
        h.put("x-t", String.valueOf(t));
        h.put("x-app-ver", "10.68.0");
        h.put("x-features", "27");
        h.put("x-ttid", TTID);
        h.put("x-sign", xSign);
        h.put("x-umt", xUmt);
        h.put("x-mini-wua", xWua);
        h.put("x-sgext", xSgext);
        // 注意：禁止 x-pv（实测必触发 PROTOPARAM_MISSED）
        if (mHeaders) {
            h.put("m-pv", "8.1.0");
            h.put("m-appkey", APP_KEY);
            h.put("m-sign", xSign);
            h.put("m-t", "1");
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
        if (is == null) { System.out.println("[" + label + "] HTTP " + code + " no body"); return; }
        if ("gzip".equalsIgnoreCase(conn.getHeaderField("Content-Encoding"))) is = new GZIPInputStream(is);
        String resp = readAll(is);
        String bx = conn.getHeaderField("bxpunish");
        conn.disconnect();

        String ret;
        String dataPreview;
        try {
            com.alibaba.fastjson.JSONObject j = com.alibaba.fastjson.JSON.parseObject(resp);
            ret = String.valueOf(j.get("ret"));
            Object d = j.get("data");
            dataPreview = d == null ? "null" : String.valueOf(d);
            if (dataPreview.length() > 300) dataPreview = dataPreview.substring(0, 300) + "...";
        } catch (Exception e) {
            ret = resp.length() > 120 ? resp.substring(0, 120) : resp;
            dataPreview = "";
        }
        boolean real = ret.contains("SUCCESS");
        System.out.println("[" + (real ? "★真实数据★ " : "") + label + "] HTTP " + code
                + " ret=" + ret + (bx != null ? " bxpunish=" + bx : ""));
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
