package com.taobao.search.sign;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 外部签名服务后端（RPC）——接入「有效 native 签名」的合规途径。
 *
 * 把 (api, version, appKey, t, data, token, cookie) POST 给用户自建的签名服务，
 * 典型是另起进程的 unidbg-server（即以本项目同源的 SpringBoot 骨架暴露的 HTTP 签名接口），
 * 或真机上跑的 frida-rpc 签名服务。签名由用户自己持有、自己授权的设备/环境产生，
 * 本工程不内置、也不尝试离线伪造 libsgmain 的 x-sign。
 *
 * 期望响应 JSON（平铺或包在 data 里均可）：
 *   {"sign":"...", "x-sign":"...", "x-sgext":"...", "x-mini-wua":"...", "t":"..."}
 * 请求头 sign.rpc.token（可选）会作为 X-Auth-Token 传给签名服务。
 */
@Component
public class RpcMtopSigner implements MtopSigner {

    private static final Logger log = LoggerFactory.getLogger(RpcMtopSigner.class);

    @Value("${sign.rpc.url:}")
    private String url;

    @Value("${sign.rpc.token:}")
    private String authToken;

    @Value("${sign.rpc.timeout-ms:5000}")
    private int timeoutMs;

    /** 真机 RPC 后端可回传设备身份；开启后自动同步给请求侧，保证签名与请求头 utdid/deviceId 一致 */
    @Value("${sign.rpc.sync-device:true}")
    private boolean syncDevice;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private com.taobao.search.service.HumanBehaviorSimulator human;

    private volatile boolean deviceSynced;

    @Override
    public String backend() { return "rpc"; }

    @Override
    public Map<String, String> sign(String api, String version, String appKey, long t, String data) {
        return sign(api, version, appKey, t, data, null, null);
    }

    @Override
    public Map<String, String> sign(String api, String version, String appKey, long t,
                                    String data, String token, String cookie) {
        return sign(api, version, appKey, t, data, token, cookie, null);
    }

    @Override
    public Map<String, String> sign(String api, String version, String appKey, long t,
                                    String data, String token, String cookie, SignContext ctx) {
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalStateException("sign.rpc.url 未配置：请指向自建的 unidbg-server / 真机签名服务");
        }
        Map<String, Object> body = new LinkedHashMap<String, Object>();
        body.put("api", api);
        body.put("version", version);
        body.put("appKey", appKey);
        body.put("t", t);
        body.put("data", data);
        if (token != null) body.put("token", token);
        if (cookie != null) body.put("cookie", cookie);
        // 真机 RPC 需要设备上下文：把 SignContext 与按真机 22 段格式拼好的 INPUT 一并透传，
        // 由签名服务用真机 signRequest 对同一 INPUT 签名，避免签名 payload 与请求头 utdid 不一致。
        if (ctx != null) {
            Map<String, String> c = new LinkedHashMap<String, String>();
            c.put("utdid", ctx.getUtdid());
            c.put("deviceId", ctx.getDeviceId());
            c.put("sid", ctx.getSid());
            c.put("xFeatures", ctx.getXFeatures());
            body.put("ctx", c);
            body.put("input", ctx.buildInput(appKey, md5(data), t, api, version));
        }
        if (syncDevice && !deviceSynced) syncRemoteDevice();

        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            if (authToken != null && !authToken.trim().isEmpty()) {
                conn.setRequestProperty("X-Auth-Token", authToken.trim());
            }
            OutputStream os = conn.getOutputStream();
            os.write(JSON.toJSONString(body).getBytes("UTF-8"));
            os.flush();
            os.close();

            int code = conn.getResponseCode();
            InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            if (is != null) {
                byte[] buf = new byte[2048];
                int n;
                while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
                is.close();
            }
            String raw = new String(bos.toByteArray(), "UTF-8");
            JSONObject jo = JSON.parseObject(raw);
            if (jo == null) throw new IllegalStateException("签名服务返回非 JSON: " + raw);
            // 只有当 data 值是真正的 JSONObject 时才展开；真机桥接会把「搜索 data」原样回显为
            // 字符串（合法 JSON 文本），fastjson 的 getJSONObject 会隐式把它解析成对象，
            // 导致 payload 被错当成搜索参数、丢失 sign/x-* 字段。先判定类型再决定是否展开。
            JSONObject payload = jo;
            Object dataVal = jo.get("data");
            if (dataVal instanceof JSONObject) {
                payload = (JSONObject) dataVal;
            }

            Map<String, String> r = new LinkedHashMap<String, String>();
            for (Map.Entry<String, Object> e : payload.entrySet()) {
                if (e.getValue() == null) continue;
                String k = e.getKey();
                if ("sign".equals(k) || "t".equals(k) || "wua".equals(k)
                        || k.startsWith("x-") || k.startsWith("mtop")) {
                    r.put(k, String.valueOf(e.getValue()));
                }
            }
            if (r.isEmpty()) throw new IllegalStateException("签名服务未返回有效签名字段: " + raw);
            if (jo.getString("_rpc_backend") != null) r.put("_rpc_backend", jo.getString("_rpc_backend"));
            r.put("_rpc", url);
            return r;
        } catch (Exception e) {
            log.warn("RPC 签名失败: {}", e.getMessage());
            throw new RuntimeException("RPC 签名失败: " + e.getMessage(), e);
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /** 从签名服务的 /device 拉取真机身份，避免伪造 utdid 与真机签名内嵌设备不一致 */
    private void syncRemoteDevice() {
        deviceSynced = true; // 只尝试一次，失败不阻塞签名
        if (human == null || url == null || url.trim().isEmpty()) return;
        try {
            java.net.URI u = new java.net.URI(url);
            String deviceUrl = u.getScheme() + "://" + u.getHost() + ":" + u.getPort() + "/device";
            HttpURLConnection conn = (HttpURLConnection) new URL(deviceUrl).openConnection();
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            int code = conn.getResponseCode();
            InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            if (is != null) {
                byte[] buf = new byte[2048];
                int n;
                while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
                is.close();
            }
            JSONObject d = JSON.parseObject(new String(bos.toByteArray(), "UTF-8"));
            conn.disconnect();
            if (d == null) return;
            human.adoptRemoteDevice(
                    d.getString("utdid"), d.getString("deviceId"), d.getString("sid"),
                    d.getString("umt"), d.getString("ttid"));
            log.info("已从真机 RPC 同步设备身份: utdid={} ttid={}", d.getString("utdid"), d.getString("ttid"));
        } catch (Exception e) {
            log.warn("同步真机设备身份失败（可手动配置 mtop.utdid/device-id/umt）: {}", e.getMessage());
        }
    }

    private static String md5(String s) {
        try {
            byte[] b = java.security.MessageDigest.getInstance("MD5")
                    .digest((s == null ? "" : s).getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder(b.length * 2);
            for (byte x : b) sb.append(String.format("%02x", x & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
