package com.taobao.search.probe;

import com.alibaba.fastjson.JSON;
import com.taobao.search.config.TaobaoConstants;
import com.taobao.search.sign.SecurityGuardEngine;
import com.taobao.search.sign.SignContext;

import java.io.*;
import java.net.*;
import java.util.*;

/**
 * 探针：用 unidbg 真签名调淘宝短信登录接口 smssend / smslogin。
 * 验证登录接口能否用 app 四头打通签名层、参数结构是否正确。
 *
 * 用法（见 tools/probe_sms_login.sh）：
 *   java -Djna.tmpdir=/tmp/unidbg-jna -cp <classes:test-classes:deps> \
 *        com.taobao.search.probe.SmsLoginProbe sms send <phone>
 *   java ... SmsLoginProbe sms login <phone> <smsCode> <smsSid>
 */
public class SmsLoginProbe {

    static final String GW = "https://acs.m.taobao.com/gw/";
    static final String APPKEY = "21646297";
    static final String TTID = "231200@taobao_android_10.69.10";
    static final String V = "1.0";

    public static void main(String[] args) throws Exception {
        String action = args.length > 0 ? args[0] : "sms";
        String step = args.length > 1 ? args[1] : "send";
        String phone = args.length > 2 ? args[2] : "13800138000";

        SecurityGuardEngine engine = SecurityGuardEngine.getInstance(
                com.taobao.search.sign.SgPaths.soPath(),
                com.taobao.search.sign.SgPaths.officialApk(),
                com.taobao.search.sign.SgPaths.mainZipPath(),
                com.taobao.search.sign.SgPaths.totemPath(),
                APPKEY, "10.69.10", false);
        SignContext ctx = new SignContext(
                "awJISchpPiMDADAJ3weNXszG",
                "Aiw8S8YGCUMNCOMAFfPJIdq-Pyb4740VtErxvLS58KdE",
                "", "", TTID, "openappkey=DEFAULT_AUTH", "27",
                "37.42195", "-122.084013");

        String api, data;
        if ("login".equals(step)) {
            String code = args.length > 3 ? args[3] : "";
            String sid = args.length > 4 ? args[4] : "";
            api = "mtop.alibaba.havana.login.smslogin";
            Map<String, Object> m = new LinkedHashMap<String, Object>();
            m.put("loginId", phone); m.put("countryCode", "86");
            m.put("smsCode", code); m.put("smsSid", sid);
            m.put("scene", "login"); m.put("source", "taobao");
            data = JSON.toJSONString(m);
        } else {
            api = "mtop.alibaba.havana.login.smssend";
            // 反编译 SMSLoginRequest + LoginComponent 实测字段：
            //   nick=手机号  phoneCode=国家码  countryCode  codeLength  sdkTraceId
            Map<String, Object> m = new LinkedHashMap<String, Object>();
            m.put("nick", phone); m.put("phoneCode", "86");
            m.put("countryCode", "86"); m.put("codeLength", "6");
            m.put("sdkTraceId", "sms_probe_" + System.currentTimeMillis());
            data = JSON.toJSONString(m);
        }

        long t = System.currentTimeMillis() / 1000;
        System.out.println("[PROBE] api=" + api);
        System.out.println("[PROBE] data=" + data);
        Map<String, String> sign = engine.sign(api, V, data, "r_sms_" + t, t, ctx);
        System.out.println("[PROBE] headers=" + sign);

        Map<String, String> params = new LinkedHashMap<String, String>();
        params.put("jsv", "2.7.2"); params.put("appKey", APPKEY);
        params.put("t", String.valueOf(t));
        params.put("sign", firstNonEmpty(sign, "x-sign", "sign"));
        params.put("api", api); params.put("v", V);
        params.put("type", "json"); params.put("dataType", "json");
        params.put("ttid", TTID); params.put("data", data);
        String body = encode(params);

        String url = GW + api + "/" + V + "/";
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("POST"); conn.setDoOutput(true);
        conn.setConnectTimeout(15000); conn.setReadTimeout(20000);
        conn.setRequestProperty("User-Agent", "MTOPSDK/3.1.1.7 (Android;15;Google;FP4) DeviceType(Phone)");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
        for (Map.Entry<String, String> e : sign.entrySet()) {
            if (e.getKey().startsWith("x-")) conn.setRequestProperty(e.getKey(), e.getValue());
        }
        conn.setRequestProperty("m-pv", "8.1.0");
        conn.setRequestProperty("m-appkey", APPKEY);
        conn.setRequestProperty("m-sign", params.get("sign"));
        conn.setRequestProperty("m-t", String.valueOf(t));
        conn.setRequestProperty("x-app-ver", "10.69.10");
        conn.setRequestProperty("x-features", "27");
        conn.setRequestProperty("netType", "HSPA");
        conn.setRequestProperty("nq", "3G");
        conn.setRequestProperty("f-refer", "mtop");
        conn.setRequestProperty("umt", "");
        OutputStream os = conn.getOutputStream();
        os.write(body.getBytes("UTF-8")); os.flush(); os.close();

        int code = conn.getResponseCode();
        InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
        String resp = readAll(is);
        System.out.println("[PROBE] HTTP=" + code);
        System.out.println("[PROBE] RESP=" + resp);
        for (Map.Entry<String, List<String>> e : conn.getHeaderFields().entrySet()) {
            if ("Set-Cookie".equalsIgnoreCase(e.getKey())) {
                System.out.println("[PROBE] SET-COOKIE=" + e.getValue());
            }
        }
    }

    static String firstNonEmpty(Map<String, String> m, String... keys) {
        for (String k : keys) {
            String v = m.get(k);
            if (v != null && !v.isEmpty()) return v;
        }
        return "";
    }

    static String encode(Map<String, String> p) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : p.entrySet()) {
            if (sb.length() > 0) sb.append('&');
            sb.append(e.getKey()).append('=')
              .append(URLEncoder.encode(e.getValue(), "UTF-8"));
        }
        return sb.toString();
    }

    static String readAll(InputStream is) throws Exception {
        if (is == null) return "";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096]; int n;
        while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
        return new String(bos.toByteArray(), "UTF-8");
    }
}
