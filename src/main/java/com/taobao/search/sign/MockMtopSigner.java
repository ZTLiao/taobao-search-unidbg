package com.taobao.search.sign;

import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * 离线 mock 签名后端：不依赖 SO，用于链路联调、单元测试、无补环境时的降级。
 * 生成的签名是确定性占位值（HMAC-SHA1 of 参数串），格式与真机一致但网关不认可。
 */
@Component
public class MockMtopSigner implements MtopSigner {

    @Override
    public String backend() {
        return "mock";
    }

    @Override
    public Map<String, String> sign(String api, String version, String appKey, long t, String data) {
        String input = api + "&" + version + "&" + appKey + "&" + t + "&" + data;
        String sign = md5(input);
        Map<String, String> result = new HashMap<String, String>();
        result.put("mtop_sign", sign);
        result.put("x-sign", sign);
        result.put("sign", sign);
        result.put("_mock", "true");
        return result;
    }

    private static String md5(String s) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] bytes = md.digest(s.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
