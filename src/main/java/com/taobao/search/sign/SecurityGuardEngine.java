package com.taobao.search.sign;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.wrapper.DvmInteger;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.memory.Memory;
import com.taobao.search.jni.TaobaoJni;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * SecurityGuard 签名引擎：真实模拟 libsgmainso-6.8.261102.so。
 *
 * 链路（全部实测验证）：
 *   1. 加载 SO + JNI_OnLoad（RegisterNatives -> JNICLibrary.doCommandNative）
 *   2. 10102 ("main", "6.8.261102", so路径)  -> Integer(0)
 *   3. 10101 (Context,3,"",app_SGLib,"",pkg,ver,"12",pkg,1,plugin) -> Integer(0)
 *   4. 10103/10104 插件就绪通知 -> null
 *   5. 70102 签名（12 参数） -> HashMap{x-sign, x-mini-wua, x-sgext, x-umt}
 *
 * 必须使用 unicorn 后端（dynarmic 不支持该 SO 的 AVMP 指令）。
 * 环境必须先于 SO 加载就位（IOResolver + JNI + NativeLoader）。
 */
public class SecurityGuardEngine {

    private static final Logger log = LoggerFactory.getLogger(SecurityGuardEngine.class);

    private static SecurityGuardEngine instance;

    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final DvmClass jnicLibrary;

    private final String appKey;
    private final String pkg = "com.taobao.taobao";
    private final String appVersion;
    private final String sdkVersion = "6.8.261102";

    private volatile boolean initialized = false;

    public static synchronized SecurityGuardEngine getInstance(
            String soPath, String apkPath, String mainZipPath, String totemPath,
            String appKey, String appVersion, boolean verbose) {
        if (instance == null) {
            instance = new SecurityGuardEngine(soPath, apkPath, mainZipPath, totemPath,
                    appKey, appVersion, verbose);
        }
        return instance;
    }

    private SecurityGuardEngine(String soPath, String apkPath, String mainZipPath,
                                String totemPath, String appKey, String appVersion, boolean verbose) {
        this.appKey = appKey;
        this.appVersion = appVersion;

        // JNA 已在 pom 中统一为 5.10.0（自带 darwin-aarch64 原生库），
        // 不再需要 jna_silicon/NativeLoader 预引导（其解压的 4.5.2 原生库会因版本不符被 JNA 5.10 拒绝）。

        AndroidEmulatorBuilder builder = AndroidEmulatorBuilder.for64Bit();
        builder.setProcessName(pkg);
        emulator = builder.build();

        // IO 映射：SO 回读自身 / 插件 zip / APK / 图腾；SGLib 插件 so 给空占位
        emulator.getSyscallHandler().addIOResolver(new IOResolver<AndroidFileIO>() {
            @Override
            public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emu, String path, int oflags) {
                File f = mapFile(path, soPath, apkPath, mainZipPath, totemPath);
                if (f != null && f.exists()) {
                    return FileResult.success(new SimpleFileIO(oflags, f, path));
                }
                if (path.contains("app_SGLib") && path.endsWith(".so")) {
                    return FileResult.success(new ByteArrayFileIO(oflags, path, new byte[0]));
                }
                return null;
            }
        });

        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        File apk = new File(apkPath);
        vm = emulator.createDalvikVM(apk.exists() ? apk : null);
        vm.setJni(new TaobaoJni());
        vm.setVerbose(verbose);

        DalvikModule dm = vm.loadLibrary(new File(soPath), true);
        module = dm.getModule();
        hookLiblogAssert();
        dm.callJNI_OnLoad(emulator);
        log.info("SecurityGuard SO 加载完成 base=0x{} JNI_OnLoad OK", Long.toHexString(module.base));

        jnicLibrary = vm.resolveClass("com/taobao/wireless/security/adapter/JNICLibrary");
    }

    private static File mapFile(String path, String soPath, String apkPath,
                                String mainZipPath, String totemPath) {
        if (path.endsWith("libsgmainso-6.8.261102.so")) return new File(soPath);
        if (path.endsWith("libsgmain.so")) return new File(mainZipPath);
        if (path.endsWith("com.taobao.taobao.apk") || path.endsWith("base.apk")) return new File(apkPath);
        if (path.endsWith("yw_1222.jpg")) return new File(totemPath);
        if (path.endsWith("yw_1222_midability.jpg"))
            return new File(totemPath.replace("yw_1222.jpg", "yw_1222_midability.jpg"));
        return null;
    }

    private void hookLiblogAssert() {
        try {
            Module liblog = emulator.getMemory().findModule("liblog.so");
            if (liblog == null) return;
            com.github.unidbg.Symbol sym = liblog.findSymbolByName("__android_log_assert", false);
            if (sym == null) return;
            com.github.unidbg.hook.hookzz.Dobby dobby =
                    com.github.unidbg.hook.hookzz.Dobby.getInstance(emulator);
            dobby.replace(sym, new com.github.unidbg.hook.ReplaceCallback() {
                @Override
                public com.github.unidbg.arm.HookStatus onCall(Emulator<?> emu, long origin) {
                    log.debug("__android_log_assert bypassed");
                    return com.github.unidbg.arm.HookStatus.LR(emu, 0);
                }
            });
        } catch (Throwable t) {
            log.warn("hook __android_log_assert 失败: {}", t.getMessage());
        }
    }

    private synchronized DvmObject<?> doCommand(int cmd, ArrayObject args) {
        return jnicLibrary.callStaticJniMethodObject(emulator,
                "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;", cmd, args);
    }

    /** init 链：10102 -> 10101 -> 10103/10104（幂等，状态在 native 内累积） */
    public synchronized void ensureInitialized() {
        if (initialized) return;
        doCommand(10102, new ArrayObject(
                new StringObject(vm, "main"),
                new StringObject(vm, sdkVersion),
                new StringObject(vm, new File(soPathOf()).getAbsolutePath())));

        DvmObject<?> ctx = vm.resolveClass("android/content/Context").newObject(null);
        DvmObject<?> plugin = vm.resolveClass(
                "com/alibaba/wireless/security/mainplugin/SecurityGuardMainPlugin").newObject(null);
        DvmObject<?> r1 = doCommand(10101, new ArrayObject(
                ctx,
                DvmInteger.valueOf(vm, 3),
                new StringObject(vm, ""),
                new StringObject(vm, "/data/user/0/com.taobao.taobao/app_SGLib"),
                new StringObject(vm, ""),
                new StringObject(vm, pkg),
                new StringObject(vm, appVersion),
                new StringObject(vm, "12"),
                new StringObject(vm, pkg),
                DvmInteger.valueOf(vm, 1),
                plugin));
        log.info("SG 10101 init ret={}", r1 == null ? "null" : r1.getValue());

        doCommand(10103, new ArrayObject());
        doCommand(10104, new ArrayObject());
        initialized = true;
    }

    private String soPathOf() {
        return "src/main/resources/native/arm64-v8a/libsgmainso-6.8.261102.so";
    }

    /**
     * 签名：执行 70102，返回 {x-sign, x-mini-wua, x-sgext, x-umt}（Map 的 value 是真实 Map 中取出的字符串）。
     *
     * 修复 ILEGAL_SIGN：payload 必须是真机完整的 15 段 INPUT（utdid&uid&...&x-features&7空位），
     * 且 utdid/deviceId/sid/t/dataMd5 必须与本次 HTTP 请求实际下发的值严格一致。
     * 旧实现用硬编码 utdid + 只有 3 段的 payload，必然被网关判签名非法。
     */
    public synchronized Map<String, String> sign(String api, String version, String data,
                                                 String requestId, long t, SignContext ctx) {
        ensureInitialized();
        String dataMd5 = md5(data);
        String payload = ctx.buildInput(appKey, dataMd5, t, api, version);
        log.info("70102 payload(前120字符)={}", payload.length() > 120 ? payload.substring(0, 120) : payload);
        DvmObject<?> ret = doCommand(70102, new ArrayObject(
                new StringObject(vm, appKey),          // 0 appKey
                new StringObject(vm, payload),         // 1 payload（完整 INPUT）
                DvmBoolean.valueOf(vm, false),         // 2 flag
                DvmInteger.valueOf(vm, 0),             // 3
                new StringObject(vm, api),             // 4 api
                new StringObject(vm, "pageId=&pageName=com.taobao.tao.welcome.Welcome"), // 5 page
                null, null, null,                      // 6,7,8 payload/header/query
                new StringObject(vm, requestId),       // 9 request_id
                DvmInteger.valueOf(vm, 0),             // 10
                DvmInteger.valueOf(vm, 0)));           // 11
        Map<String, String> headers = new LinkedHashMap<>();
        if (ret != null && ret.getValue() instanceof Map) {
            Map<?, ?> m = (Map<?, ?>) ret.getValue();
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (e.getKey() != null && e.getValue() != null) {
                    headers.put(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
                }
            }
        }
        return headers;
    }

    /**
     * 【仅 JNI 链路自检，已废弃，切勿用于真实网关请求】
     * 保留仅为兼容旧探针调用：payload 用硬编码 utdid + 空字段，非真机完整结构，
     * 生成的 x-sign 发给 acs.m.taobao.com 会被判 FAIL_SYS_ILLEGAL_SIGN。
     * 真实请求必须走 {@link #sign(String, String, String, String, long, SignContext)}，
     * 由 {@link SignContext#buildInput} 生成与本次请求头一致的设备身份与完整 INPUT。
     */
    @Deprecated
    public synchronized Map<String, String> sign(String api, String version, String data,
                                                 String requestId) {
        return sign(api, version, data, requestId, System.currentTimeMillis() / 1000,
                new SignContext("at88wsLQ2wUDACdd6tSLBrZ7", "", "", "", "", "", "27", "", ""));
    }

    private static String md5(String s) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] b = md.digest(s.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte x : b) sb.append(String.format("%02x", x & 0xff));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean isAvailable() {
        return jnicLibrary != null && module != null;
    }
}
