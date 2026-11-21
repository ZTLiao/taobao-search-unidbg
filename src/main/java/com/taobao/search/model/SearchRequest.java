package com.taobao.search.model;

/** 文本搜索请求 */
public class SearchRequest {
    private String q;              // 关键词
    private int page = 1;
    private int pageSize = 20;
    private String signBackend;    // 可选: h5 / rpc / unidbg / mock，覆盖全局配置
    private boolean human = true;  // 是否启用人类行为模拟

    // ===== BYO 合法凭据（可选）：用户自持的 token / Cookie，跳过自动握手 =====
    private String token;          // _m_h5_tk 的 token 部分
    private String cookie;         // 完整 Cookie 串

    public String getQ() { return q; }
    public void setQ(String q) { this.q = q; }
    public int getPage() { return page; }
    public void setPage(int page) { this.page = page; }
    public int getPageSize() { return pageSize; }
    public void setPageSize(int pageSize) { this.pageSize = pageSize; }
    public String getSignBackend() { return signBackend; }
    public void setSignBackend(String signBackend) { this.signBackend = signBackend; }
    public boolean isHuman() { return human; }
    public void setHuman(boolean human) { this.human = human; }
    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
    public String getCookie() { return cookie; }
    public void setCookie(String cookie) { this.cookie = cookie; }
}
