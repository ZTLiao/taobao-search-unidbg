package com.taobao.search.service;

import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 模拟人类操作请求：真实 UA、设备指纹、请求头、时间戳与随机抖动。
 * 这些字段对应 smali 里 ImageSearchMtopUtil.h() / InnerProtocolParamBuilderImpl 注入的公共参数。
 *
 * 注意：utdid 在真机上是设备级固定值。token 与设备/会话绑定，若每次请求都换 utdid
 * 会破坏会话一致性并触发风控，因此这里提供「会话级稳定 utdid」，仅显式 rotate 才更换。
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

    private volatile String sessionUtdid = generate();
    private volatile String sessionUa = UAS[ThreadLocalRandom.current().nextInt(UAS.length)];

    /** 会话级稳定 utdid（token 握手期间必须保持一致） */
    public String sessionUtdid() {
        return sessionUtdid;
    }

    /** 生成一个新 utdid（真机上是设备级固定值） */
    public String randomUtdid() {
        return generate();
    }

    /** 显式轮换设备身份（会作废当前 token，需重新握手） */
    public void rotate() {
        sessionUtdid = generate();
        sessionUa = UAS[ThreadLocalRandom.current().nextInt(UAS.length)];
    }

    private String generate() {
        byte[] b = new byte[12];
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
}
