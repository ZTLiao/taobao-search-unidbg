package com.taobao.search.sign;

/**
 * Native 签名上下文 —— 对应 mtopsdk InnerSignImpl (tb/n9f) 拼装的 INPUT 字段集。
 *
 * 真机 INPUT 格式（Frida hook tb.n9f.f + 多个开源 hook 交叉验证）：
 *   utdid & uid & reqbiz-ext & appKey & md5(data) & t & api & v & sid & ttid & deviceId
 *        & lat & lng & extdata & x-features & [7 个空位]
 *
 * 每一个字段都必须与本次 HTTP 请求实际下发的值严格一致，否则网关判 FAIL_SYS_ILLEGAL_SIGN。
 * 特别注意 utdid/deviceId：签名 payload 和 x-utdid / x-devid 头必须用同一个值。
 */
public class SignContext {

    private final String utdid;       // 24 位设备 id
    private final String deviceId;    // 44 位设备 id
    private final String sid;         // 32 位会话 id，未登录为空
    private final String uid;         // 用户 id，未登录为空
    private final String ttid;        // 终端 id，如 taobao@android_10.28.0
    private final String extdata;     // 如 openappkey=DEFAULT_AUTH
    private final String xFeatures;   // 如 27 / 1051
    private final String lat;         // 纬度，无则空
    private final String lng;         // 经度，无则空

    public SignContext(String utdid, String deviceId, String sid, String uid, String ttid,
                       String extdata, String xFeatures, String lat, String lng) {
        this.utdid = nz(utdid);
        this.deviceId = nz(deviceId);
        this.sid = nz(sid);
        this.uid = nz(uid);
        this.ttid = nz(ttid);
        this.extdata = nz(extdata);
        this.xFeatures = nz(xFeatures);
        this.lat = nz(lat);
        this.lng = nz(lng);
    }

    /** 拼装传给 70102 的 payload（15 段 + 7 空位）。dataMd5 由调用方按本次 data 计算。 */
    public String buildInput(String appKey, String dataMd5, long t, String api, String version) {
        StringBuilder sb = new StringBuilder();
        sb.append(utdid).append('&');                 // 0 utdid
        sb.append(uid).append('&');                   // 1 uid
        sb.append("").append('&');                    // 2 reqbiz-ext
        sb.append(appKey).append('&');                // 3 appKey
        sb.append(dataMd5).append('&');               // 4 md5(data)
        sb.append(t).append('&');                     // 5 t(秒)
        sb.append(api).append('&');                   // 6 api
        sb.append(version).append('&');               // 7 v
        sb.append(sid).append('&');                   // 8 sid
        sb.append(ttid).append('&');                  // 9 ttid
        sb.append(deviceId).append('&');              // 10 deviceId
        sb.append(lat).append('&');                   // 11 lat
        sb.append(lng).append('&');                   // 12 lng
        sb.append(extdata).append('&');               // 13 extdata
        sb.append(xFeatures).append('&');             // 14 x-features
        for (int i = 0; i < 7; i++) {                 // 15-21 空位
            if (i > 0) sb.append('&');
        }
        return sb.toString();
    }

    public String getUtdid() { return utdid; }
    public String getDeviceId() { return deviceId; }
    public String getSid() { return sid; }
    public String getXFeatures() { return xFeatures; }

    private static String nz(String s) { return s == null ? "" : s; }
}
