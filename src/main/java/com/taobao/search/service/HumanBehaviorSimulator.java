package com.taobao.search.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 模拟人类操作请求：真实 UA、设备指纹、请求头、时间戳与随机抖动。
 * 这些字段对应 smali 里 ImageSearchMtopUtil.h() / InnerProtocolParamBuilderImpl 注入的公共参数。
 *
 * 设备身份三要素（务必与 native 签名 payload 保持严格一致，否则网关判 FAIL_SYS_ILLEGAL_SIGN）：
 *   - utdid    : 24 位（真机如 XcZJFF61gMADAep76BgfX2AD），对应 x-utdid 头
 *   - deviceId : 44 位（真机如 AiN8kvbdEkyD1P3CqFhYct1a7PmMab5dj804e192TcrV），对应 x-devid
 *   - sid      : 32 位会话 id（登录后才有；未登录留空），对应 x-sid
 *
 * 这些在真机上是设备级固定值。token/sign 与设备绑定，若每次请求都换 utdid
 * 会破坏会话一致性并触发风控，因此这里提供「会话级稳定」身份，仅显式 rotate 才更换。
 */
@Component
public class HumanBehaviorSimulator {

    private static final String[] UAS = {
            "Mozilla/5.0 (Linux; Android 13; Pixel 7 Build/TQ3A.230805.001; wv) AppleWebKit/537.36 "
                    + "(KHTML, like Gecko) Version/4.0 Chrome/110.0.5481.154 Mobile Safari/537.36 TaobaoAndroid/10.28.0",
            "Mozilla/5.0 (Linux; Android 12; SM-G9910 Build/SP1A.210812.016; wv) AppleWebKit/537.36 "
                    + "(KHTML, like Gecko) Version/4.0 Chrome/108.0.5359.128 Mobile Safari/537.36 TaobaoAndroid/10.27.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 "
                    + "(KHTML, like Gecko) Mobile/15E148 TaobaoiPhone/10.28.0"
    };

    /** BYO：可注入自持的合法设备身份（真机抓包值），留空则自动生成 */
    @Value("${mtop.utdid:}")
    private String injectedUtdid;
    @Value("${mtop.device-id:}")
    private String injectedDeviceId;
    @Value("${mtop.sid:}")
    private String injectedSid;
    @Value("${mtop.lat:}")
    private String injectedLat;
    @Value("${mtop.lng:}")
    private String injectedLng;

    private volatile String sessionUtdid;
    private volatile String sessionDeviceId;
    private volatile String sessionSid;
    private volatile String sessionLat;
    private volatile String sessionLng;
    private volatile String sessionUa = UAS[ThreadLocalRandom.current().nextInt(UAS.length)];

    @javax.annotation.PostConstruct
    public void init() {
        sessionUtdid = notEmpty(injectedUtdid) ? injectedUtdid.trim() : generateUtdid();
        sessionDeviceId = notEmpty(injectedDeviceId) ? injectedDeviceId.trim() : generateDeviceId();
        sessionSid = injectedSid == null ? "" : injectedSid.trim();
        sessionLat = injectedLat == null ? "" : injectedLat.trim();
        sessionLng = injectedLng == null ? "" : injectedLng.trim();
    }

    /** 会话级稳定 utdid（24 位；签名 payload 与 x-utdid 头必须共用此值） */
    public String sessionUtdid() { return sessionUtdid; }

    /** 会话级稳定 deviceId（44 位；签名 payload 与 x-devid 头必须共用此值） */
    public String sessionDeviceId() { return sessionDeviceId; }

    /** 会话级 sid（32 位，未登录为空；签名 payload 与 x-sid 头必须共用此值） */
    public String sessionSid() { return sessionSid == null ? "" : sessionSid; }

    /** 经纬度（参与 native INPUT 段11/12；真机通常为定位值，可 BYO 注入） */
    public String sessionLat() { return sessionLat == null ? "" : sessionLat; }
    public String sessionLng() { return sessionLng == null ? "" : sessionLng; }

    public String randomUtdid() { return generateUtdid(); }
    public String randomDeviceId() { return generateDeviceId(); }

    /** 显式轮换设备身份（会作废当前 token，需重新握手） */
    public void rotate() {
        sessionUtdid = generateUtdid();
        sessionDeviceId = generateDeviceId();
        sessionUa = UAS[ThreadLocalRandom.current().nextInt(UAS.length)];
    }

    /** 18 字节 -> 24 位 base64url，与真机 utdid 长度一致 */
    private String generateUtdid() {
        byte[] b = new byte[18];
        ThreadLocalRandom.current().nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /** 33 字节 -> 44 位 base64url，与真机 deviceId 长度一致 */
    private String generateDeviceId() {
        byte[] b = new byte[33];
        ThreadLocalRandom.current().nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /** 模拟人类请求头（UA 会话内稳定，避免指纹漂移） */
    public Map<String, String> headers(String ttid, String utdid) {
        Map<String, String> h = new LinkedHashMap<String, String>();
        h.put("User-Agent", sessionUa);
        h.put("Accept", "application/json");
        h.put("Accept-Language", "zh-CN,zh;q=0.9");
        h.put("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
        h.put("Referer", "https://h5.m.taobao.com/");
        h.put("x-requested-with", "com.taobao.taobao");
        h.put("Origin", "https://h5.m.taobao.com");
        h.put("ttid", ttid);
        h.put("utd_id", utdid);
        h.put("Cache-Control", "no-cache");
        return h;
    }

    /** 人类行为延迟：250~900ms 抖动，避免机器式整点请求 */
    public void humanDelay() {
        try {
            Thread.sleep(250 + ThreadLocalRandom.current().nextInt(650));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static boolean notEmpty(String s) { return s != null && !s.trim().isEmpty(); }
}
