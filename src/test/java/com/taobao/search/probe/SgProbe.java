package com.taobao.search.probe;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import com.github.unidbg.linux.android.dvm.wrapper.DvmInteger;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.memory.Memory;
import com.taobao.search.jni.TaobaoJni;

import java.io.File;

/**
 * SecurityGuard libsgmainso-6.8.261102.so unidbg 探针。
 *
 * 用法: java SgProbe <stage> [backend]
 *   stage = onLoad            只加载 SO + JNI_OnLoad，抓 RegisterNatives 注册表
 *   stage = 10102|10101|10103|10104|10107  依次执行 init 链
 *   stage = 70102             签名命令（依赖 init 链完成）
 *   stage = all               init 链 + 签名
 *   backend = dynarmic|unicorn
 *
 * 命令序列来自公开逆向研究 + smali 佐证:
 *   10102: ("main", "6.8.261102", <so 绝对路径>) -> Integer(010102)
 *   10101: (Context, 3, "", app_SGLib, "", "com.taobao.taobao", "10.68.0", "12",
 *           "com.taobao.taobao", 1, SecurityGuardMainPlugin) -> Integer(0)
 *   10103/10104: (0) -> null  (插件就绪通知; native 起后台线程采设备信息)
 *   70102: 12 参数签名命令 -> HashMap{x-sign, x-mini-wua, x-sgext, x-gst, x-umt}
 */
public class SgProbe {

    static {
        // JNA 已统一 5.10.0（自带 darwin-aarch64），无需 NativeLoader 预引导；
        // 预引导注入的 4.5.2 原生库会因版本不符被 JNA 5.10 拒绝。
    }

    static final String RES = com.taobao.search.sign.SgPaths.RES;
    static final String APK_PATH = com.taobao.search.sign.SgPaths.officialApk();
    static final String SO_PATH = com.taobao.search.sign.SgPaths.soPath();
    static final String MAIN_ZIP = com.taobao.search.sign.SgPaths.mainZipPath();
    static final String TOTEM = com.taobao.search.sign.SgPaths.totemPath();
    static final String TOTEM_MID = com.taobao.search.sign.SgPaths.totemMidPath();

    static final String PROCESS = "com.taobao.taobao";
    static final String PKG = "com.taobao.taobao";
    static final String APP_VERSION = "10.68.0";
    static final String SDK_VERSION = "6.8.261102";
    static final String APP_KEY = "21646297";
    static final String AUTH_CODE = "12574478"; // TODO: 用真机抓包校准；smali 中 MtopConfig.authCode 无静态默认

    static AndroidEmulator emulator;
    static VM vm;
    static Module module;
    static DvmClass jnicLibrary;
    static String jnicClassHint;

    public static void main(String[] args) throws Exception {
        String stage = args.length > 0 ? args[0] : "onLoad";
        String backend = args.length > 1 ? args[1] : "dynarmic";

        build(backend);

        switch (stage) {
            case "onLoad": break;
            case "all": initChain(); doSign(); break;
            case "10102": cmd10102(); break;
            case "10101": cmd10102(); cmd10101(); break;
            case "10103": case "10104": initChain(); break;
            case "70102": initChain(); doSign(); break;
            default: doCommand(Integer.parseInt(stage), emptyArgs());
        }
        System.out.println("[PROBE] stage=" + stage + " DONE");
    }

    /** 按公开研究结论：环境必须先于 SO 加载就位 */
    static void build(String backend) throws Exception {
        AndroidEmulatorBuilder builder = AndroidEmulatorBuilder.for64Bit();
        if ("dynarmic".equals(backend)) {
            try {
                builder.addBackendFactory(new DynarmicFactory(true));
            } catch (Throwable t) {
                System.out.println("[PROBE] dynarmic 不可用，回退 unicorn: " + t);
            }
        }
        builder.setProcessName(PROCESS);
        emulator = builder.build();

        // IO 映射：SO 常回读自身路径 / 插件 zip / APK / 图腾；设备目录走虚拟 FS
        emulator.getSyscallHandler().addIOResolver(new IOResolver<com.github.unidbg.file.linux.AndroidFileIO>() {
            @Override
            public FileResult<com.github.unidbg.file.linux.AndroidFileIO> resolve(
                    Emulator<com.github.unidbg.file.linux.AndroidFileIO> emu, String path, int oflags) {
                File f = mapFile(path);
                if (f != null && f.exists()) {
                    return FileResult.success(new SimpleFileIO(oflags, f, path));
                }
                if (path.contains("app_SGLib") && path.endsWith(".so")) {
                    // 下发插件 so：真实设备上从服务端拉，模拟环境给空文件占位
                    return FileResult.success(new ByteArrayFileIO(oflags, path, new byte[0]));
                }
                return null;
            }
        });

        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        File apk = new File(APK_PATH);
        vm = emulator.createDalvikVM(apk.exists() ? apk : null);
        vm.setJni(new TaobaoJni());
        vm.setVerbose(true);

        DalvikModule dm = vm.loadLibrary(new File(SO_PATH), true);
        module = dm.getModule();
        hookLiblogAssert();
        System.out.println("[PROBE] SO loaded base=0x" + Long.toHexString(module.base));
        dm.callJNI_OnLoad(emulator);
        System.out.println("[PROBE] JNI_OnLoad OK");
    }

    /**
     * SO 在模拟环境下会走到 __android_log_assert(false, ..., "Unimplemented") 哨兵分支
     * （真机不会走到），unidbg 的 liblog shim 会因此 abort。改为直接返回，继续推进流程。
     */
    static void hookLiblogAssert() {
        try {
            com.github.unidbg.Module liblog = emulator.getMemory().findModule("liblog.so");
            if (liblog == null) return;
            com.github.unidbg.Symbol sym = liblog.findSymbolByName("__android_log_assert", false);
            if (sym == null) return;
            com.github.unidbg.hook.hookzz.Dobby dobby =
                    com.github.unidbg.hook.hookzz.Dobby.getInstance(emulator);
            dobby.replace(sym, new com.github.unidbg.hook.ReplaceCallback() {
                @Override
                public com.github.unidbg.arm.HookStatus onCall(com.github.unidbg.Emulator<?> emu, long origin) {
                    System.out.println("[PROBE] __android_log_assert bypassed");
                    return com.github.unidbg.arm.HookStatus.LR(emu, 0);
                }
            });
            System.out.println("[PROBE] __android_log_assert hooked @0x" + Long.toHexString(sym.getAddress()));
        } catch (Throwable t) {
            System.out.println("[PROBE] hook liblog assert failed: " + t);
        }
    }

    static File mapFile(String path) {
        if (path.endsWith("libsgmainso-6.8.261102.so")) return new File(SO_PATH);
        if (path.endsWith("libsgmain.so")) return new File(MAIN_ZIP);
        if (path.endsWith("com.taobao.taobao.apk")) return new File(APK_PATH);
        if (path.contains("com.taobao.taobao") && path.endsWith("base.apk")) return new File(APK_PATH);
        if (path.endsWith("yw_1222.jpg")) return new File(TOTEM);
        if (path.endsWith("yw_1222_midability.jpg")) return new File(TOTEM_MID);
        return null;
    }

    /** 找到注册了 doCommandNative 的类（unidbg verbose 日志会打印 RegisterNatives） */
    @SuppressWarnings("unchecked")
    static DvmClass getJnic() {
        if (jnicLibrary != null) return jnicLibrary;
        // 历史版本是 JNICLibrary；6.8.x AVMP 后类名不可见，回退枚举已注册类
        String[] candidates = {
                "com/taobao/wireless/security/adapter/JNICLibrary",
                "com/alibaba/wireless/security/adapter/JNICLibrary",
                "com/alibaba/wireless/security/mainplugin/SecurityGuardMainPlugin"
        };
        for (String c : candidates) {
            DvmClass cls = vm.resolveClass(c);
            if (registeredNativeCount(cls) > 0) {
                jnicClassHint = c + " (" + registeredNativeCount(cls) + " natives)";
                return jnicLibrary = cls;
            }
        }
        // 兜底：直接解析目标类调 doCommandNative（RegisterNatives 未匹配时报错并给出日志线索）
        jnicClassHint = "(try JNICLibrary)";
        return jnicLibrary = vm.resolveClass("com/taobao/wireless/security/adapter/JNICLibrary");
    }

    static int registeredNativeCount(DvmClass cls) {
        try {
            java.lang.reflect.Field f = DvmClass.class.getDeclaredField("nativesMap");
            f.setAccessible(true);
            java.util.Map<String, ?> m = (java.util.Map<String, ?>) f.get(cls);
            return m == null ? 0 : m.size();
        } catch (Exception e) {
            return -1;
        }
    }

    static ArrayObject emptyArgs() { return new ArrayObject(); }

    static void initChain() {
        cmd10102();
        cmd10101();
        // 10103 / 10104: 插件就绪通知（后台线程会采集设备信息）
        doCommand(10103, emptyArgs());
        doCommand(10104, emptyArgs());
    }

    /** 10102: so 声明周期 */
    static void cmd10102() {
        doCommand(10102, new ArrayObject(
                new StringObject(vm, "main"),
                new StringObject(vm, SDK_VERSION),
                new StringObject(vm, new File(SO_PATH).getAbsolutePath())));
    }

    /** 10101: 全局 init（11 参数） */
    static void cmd10101() {
        DvmObject<?> ctx = vm.resolveClass("android/content/Context").newObject(null);
        DvmObject<?> plugin = vm.resolveClass(
                "com/alibaba/wireless/security/mainplugin/SecurityGuardMainPlugin").newObject(null);
        doCommand(10101, new ArrayObject(
                ctx,
                DvmInteger.valueOf(vm, 3),        // flags: 真机为 3
                new StringObject(vm, ""),
                new StringObject(vm, "/data/user/0/com.taobao.taobao/app_SGLib"),
                new StringObject(vm, ""),
                new StringObject(vm, PKG),
                new StringObject(vm, APP_VERSION),
                new StringObject(vm, "12"),       // os version
                new StringObject(vm, PKG),
                DvmInteger.valueOf(vm, 1),        // m24: 真机为 1
                plugin));
    }

    /**
     * 【仅 JNI 链路自检，切勿用于真实网关请求】
     * 70102: UnifiedSecurity 签名，12 参数，返回五头 HashMap。
     *
     * 这里的 3 段 payload（硬编码 utdid + appKey）只用来验证 doCommandNative 调用链能否跑通，
     * 它【不是】真机签名 INPUT，发给 acs.m.taobao.com 会被判 FAIL_SYS_ILLEGAL_SIGN。
     * 真实签名请用 SecurityGuardEngine.sign(api, version, data, requestId, t, SignContext)，
     * 由 SignContext.buildInput() 生成真机 15 段 + 7 空位的完整 INPUT（见 HOOK_GUIDE.md 第 9/10 章）。
     */
    static void doSign() {
        // 故意使用最小 3 段 payload：仅自检 JNI 可达性，非真机结构，勿模仿。
        String payload = "at88wsLQ2wUDACdd6tSLBrZ7&&&" + APP_KEY + "&&&";
        DvmObject<?> ret = doCommand(70102, new ArrayObject(
                new StringObject(vm, APP_KEY),          // 0 appKey
                new StringObject(vm, payload),          // 1 payload
                DvmBoolean.valueOf(vm, false),          // 2 flag
                DvmInteger.valueOf(vm, 0),              // 3
                new StringObject(vm, "mtop.taobao.wsearch.appsearch"), // 4 api
                new StringObject(vm, "pageId=&pageName=com.taobao.tao.welcome.Welcome"), // 5 page
                null, null, null,                       // 6,7,8 可选 payload/header/query
                new StringObject(vm, "r_1"),            // 9 request_id
                DvmInteger.valueOf(vm, 0),              // 10
                DvmInteger.valueOf(vm, 0)));            // 11
        System.out.println("[PROBE] 70102 ret = " + (ret == null ? "null" : ret.getValue()));
    }

    static DvmObject<?> doCommand(int cmd, ArrayObject args) {
        DvmClass cls = getJnic();
        System.out.println("\n[PROBE] >>> doCommandNative(" + cmd + ", ...) class=" + jnicClassHint
                + " argsLen=" + (args == null ? "null" : args.length()) + " args=" + args);
        try {
            DvmObject<?> ret = cls.callStaticJniMethodObject(emulator,
                    "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;",
                    cmd, args);
            System.out.println("[PROBE] <<< cmd=" + cmd + " ret=" +
                    (ret == null ? "null" : ret.getValue()));
            return ret;
        } catch (Throwable t) {
            System.out.println("[PROBE] <<< cmd=" + cmd + " EX=" + t);
            throw (RuntimeException) t;
        }
    }
}
