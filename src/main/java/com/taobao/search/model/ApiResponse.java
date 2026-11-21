package com.taobao.search.model;

import java.util.List;
import java.util.Map;

/**
 * 统一响应结构。
 *
 * 除业务结果外，附带链路诊断信息：gatewayRet 分类、token 状态、握手尝试轨迹、
 * 可操作提示 hint、签名后端元信息 signMeta，便于定位「卡在哪一环」。
 */
public class ApiResponse {
    private boolean success;
    private String api;
    private String ret;                 // MTOP ret[0] 原文，如 SUCCESS::调用成功
    private String signBackend;
    private String requestUrl;
    private Map<String, Object> rawData;
    private List<Map<String, Object>> items;
    private String error;

    // ===== 链路诊断 =====
    private String gatewayRet;          // SUCCESS / TOKEN_REQUIRED / RISK_CONTROL / SIGN_REJECTED / LOCAL_ERROR / FAIL
    private String tokenState;          // none / handshake / injected
    private int attempts;               // 实际请求次数（含握手重试）
    private String hint;                // 面向使用者的可操作提示
    private List<String> handshakeTrail;
    private Map<String, String> signMeta;

    public static ApiResponse ok(String api, String ret, String backend, String url,
                                 Map<String, Object> raw, List<Map<String, Object>> items) {
        ApiResponse r = new ApiResponse();
        r.success = true; r.api = api; r.ret = ret; r.signBackend = backend;
        r.requestUrl = url; r.rawData = raw; r.items = items;
        r.attempts = 1; r.gatewayRet = "SUCCESS";
        return r;
    }

    public static ApiResponse fail(String api, String backend, String error) {
        return fail(api, backend, null, error);
    }

    public static ApiResponse fail(String api, String backend, String url, String error) {
        ApiResponse r = new ApiResponse();
        r.success = false; r.api = api; r.signBackend = backend; r.requestUrl = url;
        r.ret = error; r.error = error;
        r.attempts = 1;
        return r;
    }

    public ApiResponse withDiagnostics(String gatewayRet, String tokenState, int attempts,
                                       String hint, List<String> trail, Map<String, String> signMeta) {
        this.gatewayRet = gatewayRet;
        this.tokenState = tokenState;
        this.attempts = attempts;
        this.hint = hint;
        this.handshakeTrail = trail;
        this.signMeta = signMeta;
        return this;
    }

    public boolean isSuccess() { return success; }
    public String getApi() { return api; }
    public String getRet() { return ret; }
    public String getSignBackend() { return signBackend; }
    public String getRequestUrl() { return requestUrl; }
    public Map<String, Object> getRawData() { return rawData; }
    public List<Map<String, Object>> getItems() { return items; }
    public String getError() { return error; }
    public String getGatewayRet() { return gatewayRet; }
    public String getTokenState() { return tokenState; }
    public int getAttempts() { return attempts; }
    public String getHint() { return hint; }
    public List<String> getHandshakeTrail() { return handshakeTrail; }
    public Map<String, String> getSignMeta() { return signMeta; }
}
