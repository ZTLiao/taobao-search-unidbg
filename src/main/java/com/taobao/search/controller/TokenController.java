package com.taobao.search.controller;

import com.taobao.search.model.ApiResponse;
import com.taobao.search.service.HumanBehaviorSimulator;
import com.taobao.search.service.TextSearchService;
import com.taobao.search.sign.MtopTokenManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Token / 会话管理端点：查看状态、注入自持凭据、主动触发握手、作废重来。
 * 便于把「有效签名」接入点显性化：token 要么协议握手自动获取，要么由使用者合法注入。
 */
@RestController
@RequestMapping("/api/token")
public class TokenController {

    @Autowired
    private MtopTokenManager tokenManager;

    @Autowired
    private TextSearchService textSearch;

    @Autowired
    private HumanBehaviorSimulator human;

    /** GET /api/token — 当前 token 会话状态 */
    @GetMapping
    public Map<String, Object> status() {
        return tokenManager.status();
    }

    /**
     * POST /api/token — 注入自持凭据 / 作废重来。
     * {"token":"xxx", "cookie":"_m_h5_tk=...; ..."}  注入
     * {"refresh":true}                                作废 token 并轮换设备身份
     */
    @PostMapping
    public Map<String, Object> inject(@RequestBody(required = false) Map<String, Object> body) {
        if (body != null) {
            Object refresh = body.get("refresh");
            if (Boolean.TRUE.equals(refresh) || "true".equals(String.valueOf(refresh))) {
                tokenManager.invalidate();
                human.rotate();
            }
            String tk = str(body.get("token"));
            String ck = str(body.get("cookie"));
            if (notEmpty(tk) || notEmpty(ck)) tokenManager.applyInjected(tk, ck);
        }
        return tokenManager.status();
    }

    /**
     * POST /api/token/handshake — 主动跑一次标准握手，验证「拿 token → 重算 sign → 成功」。
     * 用 h5 后端发一个轻量联想请求，返回尝试轨迹。
     */
    @PostMapping("/handshake")
    public Map<String, Object> handshake(@RequestParam(defaultValue = "连衣裙") String q) {
        tokenManager.invalidate();
        ApiResponse r = textSearch.suggest(q, "h5", false);
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        m.put("handshakeAttempts", r.getAttempts());
        m.put("gatewayRet", r.getGatewayRet());
        m.put("success", r.isSuccess());
        m.put("trail", r.getHandshakeTrail());
        m.put("hint", r.getHint());
        m.put("token", tokenManager.status());
        return m;
    }

    private static String str(Object o) { return o == null ? null : String.valueOf(o); }
    private static boolean notEmpty(String s) { return s != null && !s.trim().isEmpty(); }
}
