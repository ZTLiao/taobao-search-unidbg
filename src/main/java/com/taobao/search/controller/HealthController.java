package com.taobao.search.controller;

import com.taobao.search.sign.MtopTokenManager;
import com.taobao.search.sign.SignerRouter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/** 健康检查 + 当前配置 / token 会话概览 */
@RestController
public class HealthController {

    @Value("${search.sign-backend:h5}")
    private String backend;

    @Value("${mtop.gateway:}")
    private String gateway;

    @Value("${mtop.token-handshake.enabled:true}")
    private boolean handshakeEnabled;

    @Value("${unidbg.enabled:false}")
    private boolean unidbgEnabled;

    @Autowired
    private SignerRouter signerRouter;

    @Autowired
    private MtopTokenManager tokenManager;

    @GetMapping("/api/health")
    public Map<String, Object> health() {
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        m.put("status", "UP");
        m.put("service", "taobao-search-unidbg");
        m.put("signBackend", backend);
        m.put("availableBackends", signerRouter.availableBackends());
        m.put("tokenHandshakeEnabled", handshakeEnabled);
        m.put("gateway", gateway);
        m.put("token", tokenManager.status());
        m.put("unidbgEnabled", unidbgEnabled);
        m.put("endpoints", new String[]{
                "/api/search", "/api/suggest", "/api/image_search", "/api/image_search/path",
                "/api/token", "/api/token/handshake", "/api/health"});
        return m;
    }
}
