package com.taobao.search.service;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.taobao.search.config.TaobaoConstants;
import com.taobao.search.model.ApiResponse;
import com.taobao.search.sign.MtopTokenManager;
import com.taobao.search.sign.SignerRouter;
import com.taobao.search.sign.SignContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * MTOP 请求执行器：组装公共参数 -> 签名 -> POST 网关 -> 解析响应。
 * 对应 smali 链路: tb/u7j.a -> MtopBusiness -> InnerProtocolParamBuilderImpl -> 网关。
 *
 * 关键能力（本次完善）：标准 H5 token 握手闭环。
 *   无 token 请求 -> 网关返回 FAIL_SYS_TOKEN_* 并通过 Set-Cookie 下发 _m_h5_tk
 *   -> 解析 token -> 以 sign=MD5(token&t&appKey&data) 重算 -> 带 Cookie 重发 -> 成功。
 * 这样「有效签名 token」由协议自身自动获取，无需静态抠取或离线伪造。
 */
@Component
public class MtopHttpClient {

    private static final Logger log = LoggerFactory.getLogger(MtopHttpClient.class);

    @Value("${mtop.gateway:" + TaobaoConstants.MTOP_GATEWAY + "}")
    private String gateway;

    @Value("${mtop.app-key:" + TaobaoConstants.APP_KEY + "}")
    private String appKey;

    @Value("${mtop.ttid:" + TaobaoConstants.TTID + "}")
    private String ttid;

    @Value("${mtop.token-handshake.enabled:true}")
    private boolean handshakeEnabled;

    @Value("${mtop.token-handshake.max-retries:2}")
    private int maxRetries;

    /** 协议模式：h5=标准 H5 网关（MD5 sign）；app=App 网关（acs /gw/，x-sign + 四头） */
    @Value("${mtop.protocol:h5}")
    private String protocol;

    @Value("${mtop.app-version:" + TaobaoConstants.APP_VERSION + "}")
    private String appVersion;

    @Autowired
    private SignerRouter signerRouter;

    @Autowired
    private HumanBehaviorSimulator human;

    @Autowired
    private MtopTokenManager tokenManager;

    public ApiResponse call(String api, String version, Map<String, Object> bizParams,
                            String backend, boolean simulate) {
        return call(api, version, bizParams, backend, simulate, null, null);
    }

    /**
     * 发起 MTOP 请求（带 token 握手重试）。
     *
     * @param injectToken  可选：用户自持的 _m_h5_tk token（BYO 凭据）
     * @param injectCookie 可选：用户自持的完整 Cookie
     */
    public ApiResponse call(String api, String version, Map<String, Object> bizParams,
                            String backend, boolean simulate,
                            String injectToken, String injectCookie) {
        if (notEmpty(injectToken) || notEmpty(injectCookie)) {
            tokenManager.applyInjected(injectToken, injectCookie);
        }

        final String data = JSON.toJSONString(bizParams);
        final String backendUsed = signerRouter.backendName(backend);
        final boolean needToken = signerRouter.needsToken(backend);
        final int maxAttempts = (handshakeEnabled && needToken) ? Math.max(1, maxRetries + 1) : 1;

        List<String> trail = new ArrayList<String>();
        Map<String, String> signMeta = new LinkedHashMap<String, String>();
        String lastUrl = null;
        ApiResponse lastFail = null;

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            long t = System.currentTimeMillis() / 1000;
            String utdid = human.sessionUtdid();
            String deviceId = human.sessionDeviceId();
            String sid = human.sessionSid();
            // rpc 后端会从真机同步设备身份，ttid 必须一起同步，保证签名 INPUT/form/header/data 同源
            String effTtid = human.effectiveTtid(ttid);
            boolean appMode = "app".equalsIgnoreCase(protocol);
            // token 始终透传给签名后端（h5 用它算 sign，rpc 签名服务可能也需要）；
            // needToken 只决定本客户端是否驱动「拿 token → 重算 sign → 重试」握手闭环
            String token = tokenManager.token();
            String cookie = tokenManager.cookie();

            // 设备身份三要素：签名 payload 与 HTTP 头必须共用同一组值，
            // 否则 native x-sign 校验 utdid/deviceId 不一致 -> FAIL_SYS_ILLEGAL_SIGN
            SignContext signCtx = new SignContext(utdid, deviceId, sid, "", effTtid,
                    "openappkey=DEFAULT_AUTH", "27", human.sessionLat(), human.sessionLng());
            Map<String, String> sign = signerRouter.sign(api, version, appKey, t, data,
                    backend, token, cookie, signCtx);
            signMeta = extractMeta(sign);

            Map<String, String> params = buildParams(api, version, t, data, sign);
            String traceId = human.traceId();
            Map<String, String> headers = human.headers(effTtid, utdid);
            for (Map.Entry<String, String> e : sign.entrySet()) {
                if (e.getKey().startsWith("x-")) headers.put(e.getKey(), e.getValue());
            }
            if (cookie != null && !cookie.isEmpty()) headers.put("Cookie", cookie);

            // App 协议（实测穿越 TMD 前置风控的关键形态）：
            //   POST {gateway}{api}/{v}/（无 query），参数全在 form body；
            //   UA 用 mtopsdk 原生形态；去掉 H5 专有头（Referer/Origin/x-requested-with）
            //   额外携带 x-t/x-app-ver/x-pv/x-features/x-utdid/x-c-traceid
            String url;
            if (appMode) {
                url = gateway + api + "/" + version + "/";
                // 真机 mtopsdk UA（hook 实测值，含机型），旧的 Xiaomi/MI 9 已过时
                headers.put("User-Agent", human.appUa());
                headers.remove("Referer");
                headers.remove("Origin");
                headers.remove("x-requested-with");
                headers.remove("ttid");
                headers.remove("utd_id");
                headers.remove("Accept-Language");
                headers.remove("Cache-Control");
                // 真机完整头族（Frida hook InnerProtocolParamBuilderImpl.buildParams 实测）：
                //   x-t / x-app-ver / x-features / x-app-conf-v / x-c-traceid / x-falco-id
                //   x-page-url / x-page-name / f-refer / netType / nq / umt
                headers.put("x-t", String.valueOf(t));
                headers.put("x-app-ver", appVersion);
                headers.put("x-features", "27");
                headers.put("x-app-conf-v", human.sessionAppConfV());
                headers.put("x-c-traceid", traceId);
                headers.put("x-falco-id", traceId);
                headers.put("x-page-url", "taobao://s.taobao.com/search");
                headers.put("x-page-name", "com.taobao.search.uniform.SearchActivity");
                headers.put("f-refer", "mtop");
                headers.put("netType", "HSPA");
                headers.put("nq", "3G");
                headers.put("umt", human.sessionUmt());
                headers.put("x-utdid", utdid);
                headers.put("x-devid", deviceId);
                if (sid != null && !sid.isEmpty()) headers.put("x-sid", sid);
                // 注意：实测 x-pv 头会触发 FAIL_SYS_PROTOPARAM_MISSED，不能携带
                //
                // ===== m-* 新协议头族（2026-11-22 真机对照实验决定性发现）=====
                // 缺 m-pv 时网关稳定返回 FAIL_SYS_PROTOVER_MISSED::缺少协议版本m-pv，
                // 签名再真也过不了这一层。m-* 头族是独立于 x-sign 的强制性协议门槛：
                //   m-pv      协议版本，值不敏感（6.3/8.1.0/10.0.0 均通过完整性校验）
                //   m-appkey  应用 key，与 form.appKey 一致
                //   m-sign    内容不敏感（实测 x-sign/任意串/空值均可过协议层；
                //             服务端在 m-t 有效期内不校验其内容，故无需逆向新算法）
                //   m-t       必须是「当前秒级时间戳」——这是关键！固定值(如1)会
                //             触发 FAIL_SYS_REQUEST_EXPIRED；±120s 内均接受。
                // 带齐且 m-t=t 后，协议层被突破，直接落到 FAIL_SYS_USER_VALIDATE
                // (bx-action=login) —— 即登录态层，与真机 UI 搜索卡在同一关。
                String mSign = pickSign(sign);
                if (mSign == null || mSign.isEmpty()) mSign = String.valueOf(t);
                headers.put("m-pv", "8.1.0");
                headers.put("m-appkey", appKey);
                headers.put("m-sign", mSign);
                headers.put("m-t", String.valueOf(t));
                log.debug("[{}] m-* 协议头族已附加 m-pv=8.1.0 m-t={}", api, t);
            } else {
                url = gateway + api + "/" + version + "/?" + encode(params);
            }
            lastUrl = url;
            if (simulate) human.humanDelay();

            RawResponse rr = post(url, headers, encode(params));
            boolean tokenUpdated = tokenManager.absorb(rr.setCookies);

            ApiResponse parsed = parse(api, backendUsed, url, rr.body);
            String gatewayRet = classify(parsed.getRet());
            String line = String.format("attempt#%d ret=%s tokenUpdated=%s token=%s",
                    attempt, gatewayRet, tokenUpdated,
                    tokenManager.hasToken() ? "present" : "none");
            trail.add(line);
            log.info("[{}] {}", api, line);

            boolean tokenErr = "TOKEN_REQUIRED".equals(gatewayRet)
                    || tokenManager.isTokenError(parsed.getRet());
            boolean retryable = handshakeEnabled && tokenErr && attempt < maxAttempts;

            if (parsed.isSuccess()) {
                return parsed.withDiagnostics("SUCCESS", tokenManager.source(),
                        attempt, null, trail, signMeta);
            }
            if (retryable) {
                // 网关若未随错误响应下发 Set-Cookie，主动发一次探测请求换 token
                if (!tokenUpdated) probeHandshake(api, version, backend, utdid);
                lastFail = parsed;
                continue;
            }
            ApiResponse out = parsed.withDiagnostics(gatewayRet, tokenManager.source(), attempt,
                    hintFor(gatewayRet, rr.headers, parsed.getRet()), trail, signMeta);
            String punishUrl = extractPunishUrl(rr.headers);
            if (punishUrl != null) out.setPunishUrl(punishUrl);
            return out;
        }

        ApiResponse base = lastFail != null ? lastFail
                : ApiResponse.fail(api, backendUsed, lastUrl, "握手重试耗尽");
        return base.withDiagnostics("TOKEN_REQUIRED", tokenManager.source(), trail.size(),
                "token 握手重试耗尽：请检查网关是否下发 _m_h5_tk(Set-Cookie)，"
                        + "或通过 mtop.token / mtop.cookie 注入自持凭据",
                trail, signMeta);
    }

    /** 组装网关参数：h5 模式为标准 H5 query；app 模式附加 utdid/uid/sid（进 form body） */
    private Map<String, String> buildParams(String api, String version, long t,
                                            String data, Map<String, String> sign) {
        Map<String, String> p = new LinkedHashMap<String, String>();
        p.put("jsv", "2.7.2");
        p.put("appKey", appKey);
        p.put("t", String.valueOf(t));
        p.put("sign", pickSign(sign));
        p.put("api", api);
        p.put("v", version);
        p.put("type", TaobaoConstants.API_TYPE_JSON);
        p.put("dataType", TaobaoConstants.API_TYPE_JSON);
        p.put("ttid", human.effectiveTtid(ttid));
        p.put("data", data);
        if ("app".equalsIgnoreCase(protocol)) {
            // 真机 InnerProtocolParamBuilderImpl.buildParams 实测公共参数（未登录场景）：
            //   appKey=21646297, utdid(24), deviceId/sid/uid=null(未登录但仍在 form 中),
            //   umt(umid 设备指纹), extdata=openappkey=DEFAULT_AUTH, x-features=27,
            //   x-app-conf-v=0, netType=HSPA, nq=3G, f-refer=mtop, x-app-ver,
            //   x-page-url / x-page-name（场景标识）
            p.put("appKey", appKey);
            p.put("utdid", human.sessionUtdid());
            p.put("deviceId", "");
            p.put("sid", "");
            p.put("uid", "");
            p.put("umt", human.sessionUmt());
            p.put("extdata", "openappkey=DEFAULT_AUTH");
            p.put("x-features", "27");
            p.put("x-app-conf-v", human.sessionAppConfV());
            p.put("x-app-ver", appVersion);
            p.put("netType", "HSPA");
            p.put("nq", "3G");
            p.put("f-refer", "mtop");
            p.put("x-page-url", "taobao://s.taobao.com/search");
            p.put("x-page-name", "com.taobao.search.uniform.SearchActivity");
        }
        return p;
    }

    private String pickSign(Map<String, String> sign) {
        if ("app".equalsIgnoreCase(protocol)) {
            // App 协议：sign 位放 native x-sign
            String s = sign.get("x-sign");
            if (s == null) s = sign.get("mtop_sign");
            if (s == null) s = sign.get("sign");
            return s == null ? "" : s;
        }
        String s = sign.get("sign");
        if (s == null) s = sign.get("mtop_sign");
        if (s == null) s = sign.get("x-sign");
        return s == null ? "" : s;
    }

    /** 探测握手：_token 为空时发一次最小请求，仅用于换取 Set-Cookie */
    private void probeHandshake(String api, String version, String backend, String utdid) {
        long t = System.currentTimeMillis() / 1000;
        Map<String, String> sign = signerRouter.sign(api, version, appKey, t, "{}",
                backend, null, null);
        Map<String, String> params = buildParams(api, version, t, "{}", sign);
        String url = gateway + api + "/" + version + "/"
                + ("app".equalsIgnoreCase(protocol) ? "" : "?" + encode(params));
        RawResponse rr = post(url, human.headers(human.effectiveTtid(ttid), utdid), encode(params));
        boolean ok = tokenManager.absorb(rr.setCookies);
        log.info("probeHandshake tokenUpdated={}", ok);
    }

    private String encode(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : params.entrySet()) {
            if (sb.length() > 0) sb.append('&');
            sb.append(e.getKey()).append('=').append(urlEncode(String.valueOf(e.getValue())));
        }
        return sb.toString();
    }

    private String urlEncode(String s) {
        try {
            return URLEncoder.encode(s, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            return s;
        }
    }

    /** 一次 HTTP 往返：body + 所有 Set-Cookie（握手 token 就在其中）+ 关键响应头（bixi 风控） */
    private static class RawResponse {
        String body = "";
        int code = 0;
        List<String> setCookies = new ArrayList<String>();
        Map<String, String> headers = new LinkedHashMap<String, String>();
    }

    private RawResponse post(String url, Map<String, String> headers, String body) {
        RawResponse rr = new RawResponse();
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(20000);
            conn.setInstanceFollowRedirects(false);
            for (Map.Entry<String, String> e : headers.entrySet()) {
                conn.setRequestProperty(e.getKey(), e.getValue());
            }
            OutputStream os = conn.getOutputStream();
            os.write(body.getBytes("UTF-8"));
            os.flush();
            os.close();

            rr.code = conn.getResponseCode();
            for (Map.Entry<String, List<String>> e : conn.getHeaderFields().entrySet()) {
                if (e.getKey() == null || e.getValue() == null || e.getValue().isEmpty()) continue;
                String k = e.getKey();
                if ("Set-Cookie".equalsIgnoreCase(k)) {
                    rr.setCookies.addAll(e.getValue());
                } else {
                    rr.headers.put(k, String.valueOf(e.getValue().get(0)));
                }
            }
            InputStream is = rr.code >= 400 ? conn.getErrorStream() : conn.getInputStream();
            if (is != null) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                int n;
                while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
                is.close();
                rr.body = new String(bos.toByteArray(), "UTF-8");
            }
            if (rr.body.isEmpty()) {
                rr.body = "{\"ret\":[\"FAIL_LOCAL_EXCEPTION::empty body HTTP " + rr.code + "\"]}";
            }
        } catch (Exception e) {
            log.warn("MTOP HTTP 请求异常: {}", e.getMessage());
            rr.body = "{\"ret\":[\"FAIL_LOCAL_EXCEPTION::" + esc(e.getMessage()) + "\"]}";
        } finally {
            if (conn != null) conn.disconnect();
        }
        return rr;
    }

    /** 解析 MTOP 响应：ret[0] = SUCCESS::... / FAIL_xxx，data 里取商品列表 */
    private ApiResponse parse(String api, String backend, String url, String raw) {
        try {
            JSONObject jo = JSON.parseObject(raw);
            if (jo == null) return ApiResponse.fail(api, backend, url, "响应为空: " + raw);
            JSONArray ret = jo.getJSONArray("ret");
            String retStr = ret != null && !ret.isEmpty() ? ret.getString(0) : "";
            JSONObject data = jo.getJSONObject("data");
            Map<String, Object> rawData = data != null ? data : new LinkedHashMap<String, Object>();
            List<Map<String, Object>> items = extractItems(data);
            if (retStr.startsWith("SUCCESS")) {
                return ApiResponse.ok(api, retStr, backend, url, rawData, items);
            }
            return ApiResponse.fail(api, backend, url, retStr.isEmpty() ? raw : retStr);
        } catch (Exception e) {
            return ApiResponse.fail(api, backend, url,
                    "响应解析失败: " + e.getMessage() + " | raw=" + raw);
        }
    }

    /** 网关返回分类，决定是否需要握手重试 / 给用户什么提示 */
    private String classify(String ret) {
        if (ret == null) return "FAIL";
        if (ret.startsWith("SUCCESS")) return "SUCCESS";
        if (tokenManager.isTokenError(ret)) return "TOKEN_REQUIRED";
        String r = ret.toUpperCase(Locale.ROOT);
        if (r.contains("RGV587") || r.contains("USER_VALIDATE") || r.contains("SLIDE")
                || r.contains("VERIFY") || r.contains("FORBIDDEN") || ret.contains("访问被拒绝")) {
            return "RISK_CONTROL";
        }
        if (r.contains("FAIL_LOCAL") || r.contains("LOCAL_EXCEPTION")) return "LOCAL_ERROR";
        if (r.contains("SIGN") || r.contains("ILLEGAL") || r.contains("INVALID")) {
            return "SIGN_REJECTED";
        }
        return "FAIL";
    }

    private String hintFor(String gatewayRet) {
        return hintFor(gatewayRet, null, null);
    }

    private String hintFor(String gatewayRet, Map<String, String> respHeaders, String rawRet) {
        if ("TOKEN_REQUIRED".equals(gatewayRet)) {
            return "已触发 H5 token 握手但未通过：检查网关是否下发 _m_h5_tk(Set-Cookie)，"
                    + "或注入自有 token/cookie（mtop.token / 请求体 token）";
        }
        if ("RISK_CONTROL".equals(gatewayRet)) {
            String r = rawRet == null ? "" : rawRet.toUpperCase(Locale.ROOT);
            String action = respHeaders != null ? respHeaders.get("bx-action") : null;
            if (r.contains("USER_VALIDATE") || "login".equalsIgnoreCase(action)) {
                return "风控层要求登录验证（bx-action=login）："
                        + "1) 从真机/浏览器抓登录态 cookie（cookie2/unb/sktrack 或 sid/uid）"
                        + "注入：POST /api/token {\"cookie\":\"...\"}；"
                        + "2) 或用 punishUrl 在浏览器完成验证后取 x5sec 再注入并重试（网关已标记 bx-retry=true）";
            }
            if (r.contains("RGV587") && r.contains("SM")) {
                return "网关前置设备指纹层拦截（RGV587::SM，TMD 无感验证）："
                        + "需更高保真设备指纹（umid/x-umt 当前为全零、DeviceInfoCapturer 采集为空）。"
                        + "App 协议模式 mtop.protocol=app + unidbg 后端已实测可穿越该层";
            }
            return "命中网关风控（滑块/设备/账号校验）。这不属于签名层：需真实设备凭据与账号授权，"
                    + "建议改用官方开放平台 API；本工程不提供风控绕过能力";
        }
        if ("SIGN_REJECTED".equals(gatewayRet)) {
            return "签名未被网关认可。H5 使用 sign=MD5(token&t&appKey&data)；app 私有 x-sign "
                    + "需合法签名源：配置 sign.rpc.url 对接自建 unidbg-server/真机签名服务，或注入自持凭据";
        }
        if ("LOCAL_ERROR".equals(gatewayRet)) {
            return "本地网络/解析异常：检查 mtop.gateway 可达性、超时与返回体格式";
        }
        return "网关返回失败：可切换 signBackend，或查看 handshakeTrail / rawData 定位卡点";
    }

    /** 从 bixi 风控响应头提取验证页 URL（Location 头，punish 页面） */
    private String extractPunishUrl(Map<String, String> respHeaders) {
        if (respHeaders == null) return null;
        for (String k : new String[]{"Location", "location"}) {
            String v = respHeaders.get(k);
            if (v != null && v.contains("punish")) return v;
        }
        return null;
    }

    private Map<String, String> extractMeta(Map<String, String> sign) {
        Map<String, String> m = new LinkedHashMap<String, String>();
        for (Map.Entry<String, String> e : sign.entrySet()) {
            if (e.getKey().startsWith("_")) m.put(e.getKey(), e.getValue());
        }
        return m;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> extractItems(JSONObject data) {
        List<Map<String, Object>> items = new ArrayList<Map<String, Object>>();
        if (data == null) return items;
        String[] keys = {"resultList", "items", "list", "result", "auctionList"};
        for (String k : keys) {
            JSONArray arr = data.getJSONArray(k);
            if (arr != null) {
                for (int i = 0; i < arr.size(); i++) {
                    Object o = arr.get(i);
                    if (o instanceof JSONObject) items.add((Map<String, Object>) o);
                }
                if (!items.isEmpty()) break;
            }
        }
        if (items.isEmpty()) {
            for (Map.Entry<String, Object> e : data.entrySet()) {
                if (e.getValue() instanceof JSONArray) {
                    JSONArray arr = (JSONArray) e.getValue();
                    for (int i = 0; i < arr.size() && i < 20; i++) {
                        Object o = arr.get(i);
                        if (o instanceof JSONObject) items.add((Map<String, Object>) o);
                    }
                    if (!items.isEmpty()) break;
                }
            }
        }
        return items;
    }

    private static String esc(String s) {
        return s == null ? "" : s.replace("\"", "'").replace("\n", " ").replace("\r", " ");
    }

    private static boolean notEmpty(String s) { return s != null && !s.trim().isEmpty(); }
}
