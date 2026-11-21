package com.taobao.search.model;

/**
 * 图片搜索（拍立淘）请求。
 * 支持三种图片输入：base64 / 公网 URL / 本地文件路径（服务端读取后转 base64）。
 */
public class ImageSearchRequest {
    private String imageBase64;   // 纯 base64（不含 data: 前缀）
    private String imageUrl;      // 已上传图片的 URL（走 searchimg 参数 + region 路径）
    private String imagePath;     // 服务端本地路径
    private String region;        // 框选区域 "l,r,t,b"，默认全图
    private String signBackend;   // h5 / rpc / unidbg / mock
    private boolean human = true;
    private int quality = 70;     // JPEG 压缩质量，对应 BitmapUtil.encodeBitmap(bmp, JPEG, 70)

    // ===== BYO 合法凭据（可选）=====
    private String token;
    private String cookie;

    public String getImageBase64() { return imageBase64; }
    public void setImageBase64(String imageBase64) { this.imageBase64 = imageBase64; }
    public String getImageUrl() { return imageUrl; }
    public void setImageUrl(String imageUrl) { this.imageUrl = imageUrl; }
    public String getImagePath() { return imagePath; }
    public void setImagePath(String imagePath) { this.imagePath = imagePath; }
    public String getRegion() { return region; }
    public void setRegion(String region) { this.region = region; }
    public String getSignBackend() { return signBackend; }
    public void setSignBackend(String signBackend) { this.signBackend = signBackend; }
    public boolean isHuman() { return human; }
    public void setHuman(boolean human) { this.human = human; }
    public int getQuality() { return quality; }
    public void setQuality(int quality) { this.quality = quality; }
    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
    public String getCookie() { return cookie; }
    public void setCookie(String cookie) { this.cookie = cookie; }
}
