package com.taobao.search.sign;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * SG 补环境所需资源路径解析（跨机器、跨 jar 可移植）。
 *
 * 历史代码把官方淘宝 APK 路径写死成原作者 macOS 路径
 * /Users/liaozetao/Projects/ReaProjects/app/com.taobao.taobao.apk，
 * 且 SO/totem 用相对 CWD 路径 —— 换机器或打成 jar 即失败：
 *   - IOResolver 无法把 base.apk 映射到官方 APK -> SG 读不到官方签名 -> 1927
 *   - SO 相对路径在 jar 内不存在 -> loadLibrary 失败
 *
 * 现在资源随工程打包：
 *   src/main/resources/native/arm64-v8a/libsgmainso-6.8.261102.so
 *   src/main/resources/native/arm64-v8a/libsgmain.so
 *   src/main/resources/native/totem/yw_1222.jpg (+ _midability)
 *   src/main/resources/native/com.taobao.taobao.apk   (91M 官方包)
 *
 * 解析策略（按优先级）：
 *   1) JVM 系统属性 -Dunidbg.apkPath / -Dunidbg.apk-path 或环境变量 TAOBAO_APK（外部覆盖）
 *   2) classpath 资源（jar 内）：首次调用时解压到临时目录并缓存，返回解压后的 File
 *   3) 开发期工作区相对路径 src/main/resources/native/...（存在则直接用，省去解压 91M）
 */
public final class SgPaths {

    private static final Logger log = LoggerFactory.getLogger(SgPaths.class);

    private SgPaths() {}

    /** classpath 资源根（jar 内路径，无前导 /） */
    public static final String CP_ROOT = "native";
    public static final String CP_SO = CP_ROOT + "/arm64-v8a/libsgmainso-6.8.261102.so";
    public static final String CP_MAIN_ZIP = CP_ROOT + "/arm64-v8a/libsgmain.so";
    public static final String CP_TOTEM = CP_ROOT + "/totem/yw_1222.jpg";
    public static final String CP_TOTEM_MID = CP_ROOT + "/totem/yw_1222_midability.jpg";
    public static final String CP_APK = CP_ROOT + "/com.taobao.taobao.apk";

    /** 开发期工作区相对路径（保持历史常量名，供 SgProbe 等引用） */
    public static final String RES = "src/main/resources/native";
    public static final String SO = RES + "/arm64-v8a/libsgmainso-6.8.261102.so";
    public static final String MAIN_ZIP = RES + "/arm64-v8a/libsgmain.so";
    public static final String TOTEM = RES + "/totem/yw_1222.jpg";
    public static final String TOTEM_MID = RES + "/totem/yw_1222_midability.jpg";

    private static volatile File extractedDir;

    /** 官方淘宝 APK：外部覆盖 > classpath 资源(解压) > 工作区相对路径 */
    public static String officialApk() {
        String override = firstNonBlank(
                System.getProperty("unidbg.apkPath"),
                System.getProperty("unidbg.apk-path"),
                System.getenv("TAOBAO_APK"));
        if (override != null && new File(override).exists()) {
            log.info("SG APK 使用外部覆盖路径: {}", override);
            return override;
        }
        File local = workspaceResource(CP_APK, RES + "/com.taobao.taobao.apk");
        if (local != null) return local.getAbsolutePath();
        log.warn("未找到官方淘宝 APK，SG 将以无 APK 模式启动（签名可能失败）");
        return workspaceResourceOrFallback(CP_APK, RES + "/com.taobao.taobao.apk");
    }

    /** SG so 绝对路径 */
    public static String soPath() { return abs(CP_SO, SO); }

    /** libsgmain.so 插件 zip 绝对路径 */
    public static String mainZipPath() { return abs(CP_MAIN_ZIP, MAIN_ZIP); }

    /** yw_1222.jpg 图腾绝对路径 */
    public static String totemPath() { return abs(CP_TOTEM, TOTEM); }

    public static String totemMidPath() { return abs(CP_TOTEM_MID, TOTEM_MID); }

    private static String abs(String cp, String workspace) {
        File f = workspaceResource(cp, workspace);
        if (f != null) return f.getAbsolutePath();
        return workspace; // 兜底返回相对路径（历史行为）
    }

    /** 优先用工作区相对路径（快），否则从 classpath 解压到临时目录 */
    private static File workspaceResource(String cp, String workspace) {
        File direct = new File(workspace);
        if (direct.exists()) return direct;
        return extractToTemp(cp);
    }

    private static String workspaceResourceOrFallback(String cp, String workspace) {
        File f = workspaceResource(cp, workspace);
        return f != null ? f.getAbsolutePath() : workspace;
    }

    /** 把 jar 内资源解压到系统临时目录（一次），返回解压根目录下的对应 File */
    private static synchronized File extractToTemp(String cp) {
        InputStream in = SgPaths.class.getClassLoader().getResourceAsStream(cp);
        if (in == null) return null;
        try {
            if (extractedDir == null) {
                Path tmp = Files.createTempDirectory("taobao-sg-native-");
                extractedDir = tmp.toFile();
                extractedDir.deleteOnExit();
                log.info("SG 资源解压目录: {}", extractedDir.getAbsolutePath());
            }
            File out = new File(extractedDir, cp.substring(CP_ROOT.length() + 1));
            File parent = out.getParentFile();
            if (parent != null) parent.mkdirs();
            if (!out.exists() || out.length() == 0) {
                try (InputStream src = in; OutputStream dst = new FileOutputStream(out)) {
                    byte[] buf = new byte[8192];
                    int n;
                    while ((n = src.read(buf)) != -1) dst.write(buf, 0, n);
                }
                out.deleteOnExit();
            }
            return out;
        } catch (Exception e) {
            log.warn("解压 SG 资源失败 cp={}: {}", cp, e.getMessage());
            return null;
        }
    }

    private static String firstNonBlank(String... vals) {
        for (String v : vals) {
            if (v != null && !v.trim().isEmpty()) return v.trim();
        }
        return null;
    }
}
