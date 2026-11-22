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
    /** BYO：真机 umt（umid 设备指纹，base64，随设备固定；未注入则生成占位） */
    @Value("${mtop.umt:}")
    private String injectedUmt;
    /** BYO：真机 x-app-conf-v（真机为 0） */
    @Value("${mtop.app-conf-v:0}")
    private String injectedAppConfV;

    private volatile String sessionUtdid;
    private volatile String sessionDeviceId;
    private volatile String sessionSid;
    private volatile String sessionLat;
    private volatile String sessionLng;
    private volatile String sessionUmt;
    private volatile String sessionAppConfV;
    /** 真机 ttid（RPC 同步），null 表示未同步、回退到配置值 */
    private volatile String sessionTtid;
    /** 真机 UA（RPC 同步），null 表示未同步、回退到模拟器占位 UA */
    private volatile String sessionAppUa;
    private volatile String sessionUa = UAS[ThreadLocalRandom.current().nextInt(UAS.length)];

    @javax.annotation.PostConstruct
    public void init() {
        sessionUtdid = notEmpty(injectedUtdid) ? injectedUtdid.trim() : generateUtdid();
        sessionDeviceId = notEmpty(injectedDeviceId) ? injectedDeviceId.trim() : generateDeviceId();
        sessionSid = injectedSid == null ? "" : injectedSid.trim();
        sessionLat = injectedLat == null ? "" : injectedLat.trim();
        sessionLng = injectedLng == null ? "" : injectedLng.trim();
        sessionUmt = notEmpty(injectedUmt) ? injectedUmt.trim() : generateUmt();
        sessionAppConfV = notEmpty(injectedAppConfV) ? injectedAppConfV.trim() : "0";
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

    /** umid 设备指纹（真机 base64 值，随设备固定；作为 form 的 umt 与 x-umt 头共用） */
    public String sessionUmt() { return sessionUmt == null ? "" : sessionUmt; }

    /** x-app-conf-v（真机 10.69.10 为 0） */
    public String sessionAppConfV() { return sessionAppConfV == null ? "0" : sessionAppConfV; }

    /**
     * 8 位随机 traceId（真机 x-c-traceid / x-falco-id 形态，如 7fKhyLJS）。
     * 之前用 utdid+t 是错的——真机是一次请求一随机，且 falco 与 trace 同值。
     */
    public String traceId() {
        byte[] b = new byte[6];
        ThreadLocalRandom.current().nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /** 真机 mtopsdk UA（含机型），app 协议必须使用此形态 */
    public String appUa() {
        return notEmpty(sessionAppUa) ? sessionAppUa
                : "MTOPSDK/3.1.1.7 (Android;15;Google;sdk_gphone64_arm64) DeviceType(Phone)";
    }

    public String randomUtdid() { return generateUtdid(); }
    public String randomDeviceId() { return generateDeviceId(); }

    /**
     * 采用真机 RPC 签名服务回传的设备身份。
     * 真机四头内嵌设备运行时特征，若 HTTP 头仍用随机 utdid/deviceId，
     * 服务端会判定签名与请求不一致；同步后签名与 x-utdid/x-devid/x-umt 全部同源。
     */
    public void adoptRemoteDevice(String utdid, String deviceId, String sid, String umt, String ttid) {
        if (notEmpty(utdid)) sessionUtdid = utdid.trim();
        if (notEmpty(deviceId)) sessionDeviceId = deviceId.trim();
        if (sid != null) sessionSid = sid.trim();
        if (notEmpty(umt)) sessionUmt = umt.trim();
        // ttid 必须同步：签名 INPUT 第9段、form ttid、搜索 data.ttid 三处必须同源。
        // 之前不同步导致「真机签名用 10.69 ttid，data 用旧 10.28 ttid」，服务端判定协议不一致。
        if (notEmpty(ttid)) sessionTtid = ttid.trim();
        if (notEmpty(ttid)) {
            // 由 ttid 反推真机 UA（231200@taobao_android_10.69.10 -> Android;13;...10.69.10）
            sessionAppUa = "MTOPSDK/3.1.1.7 (Android;13;unknown;TrebleDroid vanilla) DeviceType(Phone)";
        }
    }

    /** 有效 ttid：RPC 同步到真机值则优先，否则用配置值 */
    public String effectiveTtid(String configTtid) {
        return notEmpty(sessionTtid) ? sessionTtid : configTtid;
    }

    /** 显式轮换设备身份（会作废当前 token，需重新握手） */
    public void rotate() {
        sessionUtdid = generateUtdid();
        sessionDeviceId = generateDeviceId();
        sessionUmt = generateUmt();
        sessionUa = UAS[ThreadLocalRandom.current().nextInt(UAS.length)];
    }

    /** 32 字符 base64 占位 umt（真机形如 WiUB/mFLPG4qQgKiATYHzKeUIk+Xea2m，24 字节） */
    private String generateUmt() {
        byte[] b = new byte[24];
        ThreadLocalRandom.current().nextBytes(b);
        return Base64.getEncoder().encodeToString(b).substring(0, 32);
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
