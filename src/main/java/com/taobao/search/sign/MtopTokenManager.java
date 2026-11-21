package com.taobao.search.sign;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * MTOP H5 会话 / token 管理器。
 *
 * 真实 h5api.m.taobao.com 的标准握手：首次请求无 _m_h5_tk 时，网关返回
 * FAIL_SYS_TOKEN_EXPIRED / FAIL_SYS_TOKEN_EMPTY，并通过 Set-Cookie 下发
 *   _m_h5_tk=&lt;token&gt;_&lt;毫秒时间戳&gt;   _m_h5_tk_enc=...
 * 客户端取最后一个下划线前的 token，按 sign = md5(token &amp; t &amp; appKey &amp; data) 计算签名，
 * 带 Cookie 重发即通过校验。
 *
 * 本类负责：解析/缓存 Set-Cookie、维护 Cookie 会话、判断 token 类错误、
 * 支持用户注入自持凭据（BYO），并暴露状态给 health / 诊断。
 * 线程安全：Spring 单例，跨请求共享一个会话（与真机一致，token 与设备/utdid 绑定）。
 */
@Component
public class MtopTokenManager {

    private static final Logger log = LoggerFactory.getLogger(MtopTokenManager.class);

    public static final String CK_TOKEN = "_m_h5_tk";
    public static final String CK_TOKEN_ENC = "_m_h5_tk_enc";

    @Value("${mtop.token:}")
    private String injectedToken;

    @Value("${mtop.cookie:}")
    private String injectedCookie;

    @Value("${mtop.token-ttl-seconds:600}")
    private long ttlSeconds;

    private final Object lock = new Object();
    /** cookie jar，保留网关下发的所有字段（_m_h5_tk / _m_h5_tk_enc / cookie2 / t ...） */
    private final Map<String, String> jar = new LinkedHashMap<String, String>();

    private volatile String token;           // _m_h5_tk 里下划线前的部分
    private volatile String source = "none"; // none / handshake / injected
    private volatile long obtainedAt;
    private volatile int handshakes;

    @PostConstruct
    public void init() {
        if (notEmpty(injectedCookie)) {
            applyInjected(null, injectedCookie);
            log.info("MTOP 凭据已注入(配置): source=injected, token={}", mask(token));
        } else if (notEmpty(injectedToken)) {
            applyInjected(injectedToken, null);
            log.info("MTOP token 已注入(配置): token={}", mask(token));
        }
    }

    /** 返回当前可用于计算 H5 sign 的 token，可能为 null（尚未握手） */
    public String token() {
        return token;
    }

    /** 返回可直接放进 Cookie 头的完整串 */
    public String cookie() {
        synchronized (lock) {
            if (jar.isEmpty()) return null;
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, String> e : jar.entrySet()) {
                if (sb.length() > 0) sb.append("; ");
                sb.append(e.getKey()).append('=').append(e.getValue());
            }
            return sb.toString();
        }
    }

    public boolean hasToken() { return notEmpty(token); }
    public String source() { return source; }
    public int handshakeCount() { return handshakes; }
    public long ageSeconds() { return obtainedAt == 0 ? -1 : (System.currentTimeMillis() - obtainedAt) / 1000; }
    public boolean isStale() { return ttlSeconds > 0 && ageSeconds() > ttlSeconds; }

    /**
     * 吸收响应里的 Set-Cookie 列表。
     *
     * @return 是否拿到/刷新了 _m_h5_tk
     */
    public boolean absorb(List<String> setCookies) {
        if (setCookies == null || setCookies.isEmpty()) return false;
        boolean tokenChanged = false;
        synchronized (lock) {
            for (String sc : setCookies) {
                if (sc == null) continue;
                String first = sc.split(";", 2)[0].trim();
                int eq = first.indexOf('=');
                if (eq <= 0) continue;
                String k = first.substring(0, eq).trim();
                String v = first.substring(eq + 1).trim();
                if (k.isEmpty() || v.isEmpty()) continue;
                if (CK_TOKEN.equals(k) && !v.equals(jar.get(k))) tokenChanged = true;
                jar.put(k, v);
            }
            if (tokenChanged) {
                refreshTokenFromJar("handshake");
                handshakes++;
                log.info("MTOP token 握手成功: token={}, cookieKeys={}", mask(token), jar.keySet());
            }
        }
        return tokenChanged;
    }

    /** 请求级 / 配置级注入用户自持的合法凭据（BYO） */
    public void applyInjected(String tk, String ck) {
        synchronized (lock) {
            if (notEmpty(ck)) {
                for (String part : ck.split(";")) {
                    String p = part.trim();
                    int eq = p.indexOf('=');
                    if (eq > 0) jar.put(p.substring(0, eq).trim(), p.substring(eq + 1).trim());
                }
            }
            if (notEmpty(tk)) {
                String raw = tk.contains("_") ? tk : tk + "_" + System.currentTimeMillis();
                jar.put(CK_TOKEN, raw);
            }
            if (jar.containsKey(CK_TOKEN)) {
                refreshTokenFromJar("injected");
                handshakes++;
            }
        }
    }

    /** 主动作废 token（触发下一轮重新握手） */
    public void invalidate() {
        synchronized (lock) {
            jar.remove(CK_TOKEN);
            token = null;
            source = "none";
            obtainedAt = 0;
        }
    }

    /** 判断网关 ret 是否属于 token 类错误（需要握手/重算 sign 重试） */
    public boolean isTokenError(String ret) {
        if (ret == null) return false;
        String r = ret.toUpperCase(Locale.ROOT);
        return r.contains("FAIL_SYS_TOKEN_EXPIRED")
                || r.contains("FAIL_SYS_TOKEN_EMPTY")
                || r.contains("FAIL_SYS_TOKEN")
                || r.contains("TOKEN_EXPIRED")
                || r.contains("TOKEN_EMPTY")
                || r.contains("FAIL_SYS_SESSION_EXPIRED")
                || r.contains("SESSION_EXPIRED");
    }

    public Map<String, Object> status() {
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        m.put("hasToken", hasToken());
        m.put("token", mask(token));
        m.put("source", source);
        m.put("ageSeconds", ageSeconds());
        m.put("stale", isStale());
        m.put("handshakes", handshakes);
        synchronized (lock) {
            m.put("cookieKeys", new ArrayList<String>(jar.keySet()));
        }
        return m;
    }

    private void refreshTokenFromJar(String src) {
        String raw = jar.get(CK_TOKEN);
        int idx = raw == null ? -1 : raw.lastIndexOf('_');
        token = raw == null ? null : (idx > 0 ? raw.substring(0, idx) : raw);
        source = src;
        obtainedAt = System.currentTimeMillis();
    }

    private static String mask(String s) {
        if (s == null || s.length() < 8) return s;
        return s.substring(0, 4) + "****" + s.substring(s.length() - 4);
    }

    private static boolean notEmpty(String s) { return s != null && !s.trim().isEmpty(); }
}
