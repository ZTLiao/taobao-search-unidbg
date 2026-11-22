package com.taobao.search.sign;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 验证 ILEGAL_SIGN 修复的核心：native 70102 payload 必须是真机 15 段 INPUT 结构，
 * 且 utdid/deviceId/dataMd5/t 按约定拼接。
 */
public class SignContextTest {

    @Test
    public void testInputStructure() {
        String utdid = "XcZJFF61gMADAep76BgfX2AD";          // 24 位
        String deviceId = "AiN8kvbdEkyD1P3CqFhYct1a7PmMab5dj804e192TcrV"; // 44 位
        String sid = "";
        SignContext ctx = new SignContext(utdid, deviceId, sid, "",
                "taobao@android_10.28.0", "openappkey=DEFAULT_AUTH", "27", "", "");

        String md5 = "d41d8cd98f00b204e9800998ecf8427e";
        long t = 1704067200L;
        String api = "mtop.taobao.wsearch.appsearch";
        String input = ctx.buildInput("21646297", md5, t, api, "1.0");

        String[] parts = input.split("&", -1);
        // 15 段有效字段 + 7 个空位 = 22 段（末尾连续 & 由 split(-1) 保留）
        assertEquals(22, parts.length, "字段数量应为 22（15+7 空位）");
        assertEquals(utdid, parts[0], "段0=utdid");
        assertEquals("", parts[1], "段1=uid(空)");
        assertEquals("", parts[2], "段2=reqbiz-ext(空)");
        assertEquals("21646297", parts[3], "段3=appKey");
        assertEquals(md5, parts[4], "段4=md5(data)");
        assertEquals(String.valueOf(t), parts[5], "段5=t(秒)");
        assertEquals(api, parts[6], "段6=api");
        assertEquals("1.0", parts[7], "段7=v");
        assertEquals("", parts[8], "段8=sid(空)");
        assertEquals(deviceId, parts[10], "段10=deviceId");
        assertEquals("openappkey=DEFAULT_AUTH", parts[13], "段13=extdata");
        assertEquals("27", parts[14], "段14=x-features");
        System.out.println("[SignContextTest] INPUT OK = " + input);
    }

    @Test
    public void testDeviceIdLengths() {
        // 修复自证式断言：改为断言生产对象 buildInput 实际产出的段长度，而非字面量自身。
        SignContext ctx = new SignContext(
                "XcZJFF61gMADAep76BgfX2AD",
                "AiN8kvbdEkyD1P3CqFhYct1a7PmMab5dj804e192TcrV",
                "", "", "", "", "27", "", "");
        String[] parts = ctx.buildInput("21646297", "md5", 1L, "api", "1.0").split("&", -1);
        assertEquals(24, parts[0].length(), "buildInput 段0 utdid 应 24 位");
        assertEquals(44, parts[10].length(), "buildInput 段10 deviceId 应 44 位");
    }

    /** 边界：null 字段由 nz() 归一化为空串；& 等分隔符会破坏 22 段结构，此处固化当前行为以便及早发现回归。 */
    @Test
    public void testNullAndSeparatorFields() {
        SignContext nullCtx = new SignContext(null, null, null, null, null, null, null, null, null);
        String[] parts = nullCtx.buildInput("21646297", "md5", 1L, "api", "1.0").split("&", -1);
        assertEquals(22, parts.length, "null 字段归一化为 '',仍应是 22 段");
        assertEquals("", parts[0], "null utdid 应归一化为空串");

        // 字段含 & 会多出段——记录该已知限制：真实设备身份不含 &，若将来做转义需同步更新此断言。
        SignContext ampCtx = new SignContext("ut&did", "deviceId", "", "", "", "", "27", "", "");
        String[] ampParts = ampCtx.buildInput("21646297", "md5", 1L, "api", "1.0").split("&", -1);
        assertEquals(23, ampParts.length, "& 污染会使段数 +1（已知限制，真机身份不含 &）");
    }

    /**
     * 真机 ground truth：Frida hook 淘宝 10.69.10 的 JNICLibrary.doCommandNative(70102)
     * 抓到的 arg[1] 原始 INPUT。逐字段核对我们的 buildInput 还原结果。
     */
    @Test
    public void testRealDeviceGroundTruth() {
        String utdid = "awJISchpPiMDADAJ3weNXszG";
        String deviceId = "Aiw8S8YGCUMNCOMAFfPJIdq-Pyb4740VtErxvLS58KdE";
        String ttid = "231200@taobao_android_10.69.10";
        SignContext ctx = new SignContext(utdid, deviceId, "", "", ttid,
                "openappkey=DEFAULT_AUTH", "27", "37.42195", "-122.084013");
        String md5 = "f8f124264d8437ae645551f73b3e5047";
        long t = 1795313584L;
        String api = "mtop.taobao.wireless.home.newface.awesome.get";
        String input = ctx.buildInput("21646297", md5, t, api, "1.0");

        String expected = "awJISchpPiMDADAJ3weNXszG&&&21646297&f8f124264d8437ae645551f73b3e5047"
                + "&1795313584&mtop.taobao.wireless.home.newface.awesome.get&1.0"
                + "&&231200@taobao_android_10.69.10"
                + "&Aiw8S8YGCUMNCOMAFfPJIdq-Pyb4740VtErxvLS58KdE"
                + "&37.42195&-122.084013&openappkey=DEFAULT_AUTH&27&&&&&&&";
        assertEquals(expected, input, "必须与真机 70102 INPUT 逐字节一致");
        System.out.println("[SignContextTest] REAL DEVICE INPUT MATCH OK");
    }
}
