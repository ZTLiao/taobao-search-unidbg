package com.taobao.search.jni;

import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.api.ApplicationInfo;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import com.github.unidbg.linux.android.dvm.wrapper.DvmInteger;
import com.github.unidbg.linux.android.dvm.wrapper.DvmLong;

/**
 * SecurityGuard (libsgmain) 补环境 JNI。
 * 复刻开源 unidbg-server 的 DouyinJniNext 写法：对 SO 回调上来的 Java 方法逐一补返回值。
 * 真实工程需根据 vm.setVerbose(true) 打印的 JNI 调用序列持续补充 case。
 */
public class TaobaoJni extends AbstractJni {

    public static final String PROCESS_NAME = "com.taobao.taobao";
    public static final String APK_PATH = "native/com.taobao.taobao.apk";

    @Override
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/alibaba/wireless/security/open/SecException-><init>(Ljava/lang/String;I)V":
            case "com/alibaba/wireless/security/open/SecException-><init>(Ljava/lang/String;II)V":
                // native 构造异常对象（错误路径缓存或上报用），返回空实例
                return vm.resolveClass("com/alibaba/wireless/security/open/SecException").newObject(null);
            case "java/lang/Integer-><init>(I)V":
                return DvmInteger.valueOf(vm, vaList.getIntArg(0));
            case "java/lang/Long-><init>(J)V":
                return DvmLong.valueOf(vm, vaList.getLongArg(0));
            case "java/lang/Boolean-><init>(Z)V":
                return DvmBoolean.valueOf(vm, vaList.getIntArg(0) != 0);
            case "java/util/HashMap-><init>()V":
            case "java/util/HashMap-><init>(I)V":
                // 70102 结果容器：value 持有真实 Map，后续 put/最终返回都走该对象
                return vm.resolveClass("java/util/HashMap").newObject(new java.util.LinkedHashMap<String, Object>());
            default:
                return super.newObjectV(vm, dvmClass, signature, vaList);
        }
    }

    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        switch (signature) {
            case "com/alibaba/wireless/security/open/SecException-><init>(Ljava/lang/String;I)V":
                return vm.resolveClass("com/alibaba/wireless/security/open/SecException").newObject(null);
            case "java/lang/Integer-><init>(I)V":
                return DvmInteger.valueOf(vm, varArg.getIntArg(0));
            case "java/lang/Long-><init>(J)V":
                return DvmLong.valueOf(vm, varArg.getLongArg(0));
            case "java/lang/Boolean-><init>(Z)V":
                return DvmBoolean.valueOf(vm, varArg.getIntArg(0) != 0);
            case "java/util/HashMap-><init>()V":
            case "java/util/HashMap-><init>(I)V":
                // 70102 结果容器：value 持有真实 Map，后续 put/最终返回都走该对象
                return vm.resolveClass("java/util/HashMap").newObject(new java.util.LinkedHashMap<String, Object>());
            default:
                return super.newObject(vm, dvmClass, signature, varArg);
        }
    }

    @Override
    public void setStaticIntField(BaseVM vm, DvmClass dvmClass, String signature, int value) {
        switch (signature) {
            case "com/alibaba/wireless/security/mainplugin/SecurityGuardMainPlugin->sLoadVersion:I":
                // native 侧回写加载版本，宿主不关心
                return;
            default:
                super.setStaticIntField(vm, dvmClass, signature, value);
        }
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        switch (signature) {
            case "com/alibaba/wireless/security/mainplugin/SecurityGuardMainPlugin->sLoadVersion:I":
                // SDK 内部加载版本号（对齐 6.8.261102 的 010102 分发码）
                return 10102;
            case "android/os/Build$VERSION->SDK_INT:I":
                return 33; // Android 13，与 UA(Android;13) / 10101 init 参数 "13" / VERSION.RELEASE 对齐
            default:
                return super.getStaticIntField(vm, dvmClass, signature);
        }
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        switch (signature) {
            case "com/alibaba/wireless/security/mainplugin/SecurityGuardMainPlugin->sLoadVersion:I":
                return DvmInteger.valueOf(vm, 10102);
            case "android/os/Build$VERSION->SDK_INT:I":
                return DvmInteger.valueOf(vm, 33);
            // ===== Build 设备指纹：补齐后 SG 采集到完整量产机画像，不再是空/unknown =====
            case "android/os/Build->MANUFACTURER:Ljava/lang/String;":
                return new StringObject(vm, BUILD_MANUFACTURER);
            case "android/os/Build->BRAND:Ljava/lang/String;":
                return new StringObject(vm, BUILD_BRAND);
            case "android/os/Build->MODEL:Ljava/lang/String;":
                return new StringObject(vm, BUILD_MODEL);
            case "android/os/Build->DEVICE:Ljava/lang/String;":
                return new StringObject(vm, BUILD_DEVICE);
            case "android/os/Build->PRODUCT:Ljava/lang/String;":
                return new StringObject(vm, BUILD_PRODUCT);
            case "android/os/Build->BOARD:Ljava/lang/String;":
                return new StringObject(vm, BUILD_BOARD);
            case "android/os/Build->HARDWARE:Ljava/lang/String;":
                return new StringObject(vm, BUILD_HARDWARE);
            case "android/os/Build->FINGERPRINT:Ljava/lang/String;":
                return new StringObject(vm, BUILD_FINGERPRINT);
            case "android/os/Build->ID:Ljava/lang/String;":
                return new StringObject(vm, BUILD_ID);
            case "android/os/Build->DISPLAY:Ljava/lang/String;":
                return new StringObject(vm, BUILD_DISPLAY);
            case "android/os/Build->SERIAL:Ljava/lang/String;":
                return new StringObject(vm, "unknown");
            case "android/os/Build$VERSION->RELEASE:Ljava/lang/String;":
                return new StringObject(vm, "13");
            case "android/os/Build$VERSION->INCREMENTAL:Ljava/lang/String;":
                return new StringObject(vm, "V14.0.5.0.TKQCNXM");
            default:
                return super.getStaticObjectField(vm, dvmClass, signature);
        }
    }

    @Override
    public DvmObject callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        // 插件类加载器
        if (signature.contains("Plugin->getPluginClassLoader()Ljava/lang/ClassLoader;")
                || signature.contains("Plugin->getMainPluginClassLoader()Ljava/lang/ClassLoader;")) {
            return vm.resolveClass("java/lang/ClassLoader").newObject(null);
        }
        // 通用单例获取：xxx->getInstance()Lxxx; 返回该类实例。
        // 修复原有 &&/|| 优先级 bug：原写法 (idx>0 && endsWith) || contains 使条件恒真，
        // 且 idx==0 时 substring(0,0) 得到空类名导致 resolveClass 崩溃。
        int idx = signature.indexOf("->getInstance()");
        if (idx > 0 && (signature.endsWith("Lcom/taobao/dp/util/CallbackHelper;")
                || signature.contains("->getInstance()"))) {
            String cls = signature.substring(0, idx);
            return vm.resolveClass(cls).newObject(null);
        }
        if ("java/lang/Thread->currentThread()Ljava/lang/Thread;".equals(signature)) {
            return vm.resolveClass("java/lang/Thread").newObject(Thread.currentThread());
        }
        if ("java/lang/System->getProperty(Ljava/lang/String;)Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, "6");
        }
        // 通用：静态 getClassLoader / getStackTrace / StackTraceElement 家族
        DvmObject common = commonCallback(vm, signature);
        if (common != null) return common;
        // securitybody 无感风控组件（静态路径）：模拟环境返回空串让 70102 主流程继续
        if (signature.startsWith("com/alibaba/wireless/security/securitybody/SecurityBodyAdapter->doAdapter")) {
            return new StringObject(vm, "");
        }
        // 设备信息采集（静态路径）：空串探路
        if (signature.startsWith("com/taobao/wireless/security/adapter/datacollection/DeviceInfoCapturer->doCommandForString")) {
            return new StringObject(vm, "");
        }
        // SPUtility2 读
        if (signature.startsWith("com/taobao/wireless/security/adapter/common/SPUtility2->")
                && signature.contains("readFromFileUnifiedForNative")) {
            DvmObject<?> k = varArg.getObjectArg(0);
            String key = k == null ? "" : String.valueOf(k.getValue());
            return new StringObject(vm, SP_STORE.getOrDefault(key, ""));
        }
        return super.callStaticObjectMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public DvmObject callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "java/lang/Thread->currentThread()Ljava/lang/Thread;":
                return vm.resolveClass("java/lang/Thread").newObject(Thread.currentThread());
            case "android/provider/Settings$Secure->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;":
                return new StringObject(vm, "");
            case "java/lang/System->getProperty(Ljava/lang/String;)Ljava/lang/String;":
                return new StringObject(vm, "6");
            case "android/app/Application->getApplicationInfo()Landroid/content/pm/ApplicationInfo;":
                return new ApplicationInfo(vm);
            case "android/net/Uri->parse(Ljava/lang/String;)Landroid/net/Uri;":
                return vm.resolveClass("android/net/Uri").newObject(null);
            case "com/alibaba/wireless/security/mainplugin/SecurityGuardMainPlugin->getMainPluginClassLoader()Ljava/lang/ClassLoader;":
                // JNI_OnLoad 首个回调：插件类加载器
                return vm.resolveClass("java/lang/ClassLoader").newObject(null);
            // elapsedRealtime 语义是「自开机起的单调毫秒」，不能返回 epoch 墙上时钟。
            // SO 内用它做计时/超时/反调试判断，返回墙上时钟会得到错误结果。
            case "android/os/SystemClock->elapsedRealtime()J":
                return DvmLong.valueOf(vm, System.nanoTime() / 1_000_000L);
            default:
                return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
        }
    }

    // ===== 真机环境画像（路径需与 10101 init 参数同域）=====
    public static final String DATA_DIR = "/data/user/0/com.taobao.taobao";
    public static final String CODE_PATH = "/data/app/~~9j0QgXp3hA0yWk1VcJ2ZPw==/com.taobao.taobao-VeK8mPqLr2XwYz0aB1cD6e==/base.apk";

    // ===== Build 设备指纹（量产真机画像）=====
    // SG 的 DeviceInfoCapturer 采集设备指纹时会读 android.os.Build.* 静态字段。
    // 之前未补这些字段，JNI 回调落到 super 抛异常/返回空 -> 设备画像为空 ->
    // bixi 判定为非真机环境（wh_ttid=pc）。用与 UA 一致的量产机画像补齐，
    // 消除 sdk_gphone/unknown/empty 等模拟器特征。
    public static final String BUILD_MANUFACTURER = "Xiaomi";
    public static final String BUILD_BRAND = "Xiaomi";
    public static final String BUILD_MODEL = "22081212C";
    public static final String BUILD_DEVICE = "duchamp";
    public static final String BUILD_PRODUCT = "duchamp_global";
    public static final String BUILD_BOARD = "sm8250";
    public static final String BUILD_HARDWARE = "qcom";
    public static final String BUILD_FINGERPRINT =
            "Xiaomi/duchamp_global/duchamp:13/TKQ1.221114.001/V14.0.5.0.TKQCNXM:user/release-keys";
    public static final String BUILD_ID = "TKQ1.221114.001";
    public static final String BUILD_DISPLAY = "V14.0.5.0.TKQCNXM";

    @Override
    public boolean callStaticBooleanMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if (signature.startsWith("com/alibaba/wireless/security/framework/ApmMonitorAdapter->")) {
            return false; // 监控/全链路采集开关：模拟环境统一关闭
        }
        return super.callStaticBooleanMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (signature.startsWith("com/alibaba/wireless/security/framework/ApmMonitorAdapter->")) {
            return false;
        }
        return super.callStaticBooleanMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public boolean callBooleanMethod(BaseVM vm, DvmObject dvmObject, String signature, VarArg varArg) {
        if (signature.startsWith("com/alibaba/wireless/security/framework/ApmMonitorAdapter->")) {
            return false;
        }
        return super.callBooleanMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject dvmObject, String signature, VaList vaList) {
        if (signature.startsWith("com/alibaba/wireless/security/framework/ApmMonitorAdapter->")) {
            return false;
        }
        return super.callBooleanMethodV(vm, dvmObject, signature, vaList);
    }

    /** void 回调通用兜底：插件通知类方法直接吞掉 */
    private static boolean isNotifyLike(String sig) {
        return sig.startsWith("com/alibaba/wireless/security/mainplugin/SecurityGuardMainPlugin->")
                || sig.startsWith("com/alibaba/wireless/security/framework/ApmMonitorAdapter->")
                || sig.startsWith("com/alibaba/wireless/security/framework/SGApmMonitorManager->")
                || sig.startsWith("com/taobao/wireless/security/adapter/datareport/DataReportJniBridge->");
    }

    @Override
    public void callStaticVoidMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        if (isNotifyLike(signature)) return;
        super.callStaticVoidMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        if (isNotifyLike(signature)) return;
        super.callStaticVoidMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject dvmObject, String signature, VarArg varArg) {
        if (isNotifyLike(signature)) return;
        super.callVoidMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject dvmObject, String signature, VaList vaList) {
        if (isNotifyLike(signature)) return;
        super.callVoidMethodV(vm, dvmObject, signature, vaList);
    }

    // ===== SPUtility2 内存持久化（native 侧 SharedPreferences 桥）=====
    public static final java.util.Map<String, String> SP_STORE = new java.util.concurrent.ConcurrentHashMap<>();

    @Override
    public int callIntMethod(BaseVM vm, DvmObject dvmObject, String signature, VarArg varArg) {
        if ("java/lang/StackTraceElement->getLineNumber()I".equals(signature)) {
            return 0;
        }
        if (signature.startsWith("com/taobao/wireless/security/adapter/datacollection/DeviceInfoCapturer->doCommandForInt")) {
            return 0;
        }
        return super.callIntMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject dvmObject, String signature, VaList vaList) {
        if ("java/lang/StackTraceElement->getLineNumber()I".equals(signature)) {
            return 0;
        }
        return super.callIntMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public int callStaticIntMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        switch (signature) {
            case "com/uc2/crashsdk/JNIBridge->registerInfoCallback(Ljava/lang/String;IJI)I":
                return 0;
            case "com/alibaba/wireless/security/framework/utils/UserTrackMethodJniBridge->utAvaiable()I":
                return 0; // UT 埋点不可用
            default: {
                if (signature.startsWith("com/taobao/wireless/security/adapter/common/SPUtility2->")
                        && signature.contains("saveToFileUnifiedForNative")) {
                    // (key, value, path, append?) -> 保存到内存 KV，返回 0 表示成功
                    DvmObject<?> k = varArg.getObjectArg(0), v = varArg.getObjectArg(1);
                    if (k != null && v != null) {
                        SP_STORE.put(String.valueOf(k.getValue()), String.valueOf(v.getValue()));
                    }
                    return 0;
                }
                return super.callStaticIntMethod(vm, dvmClass, signature, varArg);
            }
        }
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/uc2/crashsdk/JNIBridge->registerInfoCallback(Ljava/lang/String;IJI)I":
            case "com/alibaba/wireless/security/framework/utils/UserTrackMethodJniBridge->utAvaiable()I":
                return 0;
            default: {
                if (signature.startsWith("com/taobao/wireless/security/adapter/common/SPUtility2->")
                        && signature.contains("saveToFileUnifiedForNative")) {
                    DvmObject<?> k = vaList.getObjectArg(0), v = vaList.getObjectArg(1);
                    if (k != null && v != null) {
                        SP_STORE.put(String.valueOf(k.getValue()), String.valueOf(v.getValue()));
                    }
                    return 0;
                }
                return super.callStaticIntMethodV(vm, dvmClass, signature, vaList);
            }
        }
    }

    /** 通用回调（ClassLoader / Thread / StackTraceElement / getClassLoader），命中返回 DvmObject，未命中返回 null */
    private DvmObject commonCallback(BaseVM vm, String signature) {
        if (signature.endsWith("->getClassLoader()Ljava/lang/ClassLoader;")
                || signature.endsWith("->getPluginClassLoader()Ljava/lang/ClassLoader;")
                || signature.endsWith("->getMainPluginClassLoader()Ljava/lang/ClassLoader;")) {
            return vm.resolveClass("java/lang/ClassLoader").newObject(null);
        }
        if ("java/lang/ClassLoader->findClass(Ljava/lang/String;)Ljava/lang/Class;".equals(signature)) {
            // 参数在调用处单独取，这里只标记；实际走 overload
            return null;
        }
        if ("java/lang/Thread->currentThread()Ljava/lang/Thread;".equals(signature)) {
            return vm.resolveClass("java/lang/Thread").newObject(Thread.currentThread());
        }
        if ("java/lang/Thread->getStackTrace()[Ljava/lang/StackTraceElement;".equals(signature)) {
            // 反调试/环境检测：返回伪造的常规 Android 调用栈（不暴露宿主 Java 环境）
            DvmClass ste = vm.resolveClass("java/lang/StackTraceElement");
            return new ArrayObject(
                    ste.newObject("dalvik.system.VMStack.getThreadStackTrace"),
                    ste.newObject("com.taobao.taobao.main"));
        }
        if (signature.startsWith("java/lang/StackTraceElement->")) {
            String m = signature.substring(signature.indexOf("->") + 2);
            if (m.startsWith("getClassName()") || m.startsWith("getMethodName()")
                    || m.startsWith("getFileName()")) {
                // value 在实例上，需调用者提供——此 helper 只处理静态场景，实例场景在方法内处理
                return null;
            }
            if (m.startsWith("isNativeMethod()")) return DvmBoolean.valueOf(vm, false);
        }
        return null;
    }

    @Override
    public DvmObject callObjectMethod(BaseVM vm, DvmObject dvmObject, String signature, VarArg varArg) {
        // 通用 ClassLoader 获取
        if (signature.endsWith("->getClassLoader()Ljava/lang/ClassLoader;")) {
            return vm.resolveClass("java/lang/ClassLoader").newObject(null);
        }
        if ("java/lang/ClassLoader->findClass(Ljava/lang/String;)Ljava/lang/Class;".equals(signature)) {
            return vm.resolveClass(String.valueOf(varArg.getObjectArg(0).getValue()));
        }
        if ("java/lang/Thread->currentThread()Ljava/lang/Thread;".equals(signature)) {
            return vm.resolveClass("java/lang/Thread").newObject(Thread.currentThread());
        }
        if ("java/lang/Thread->getStackTrace()[Ljava/lang/StackTraceElement;".equals(signature)) {
            // 反调试/环境检测：返回伪造的常规 Android 调用栈（不暴露宿主 Java 环境）
            DvmClass ste = vm.resolveClass("java/lang/StackTraceElement");
            return new ArrayObject(
                    ste.newObject("dalvik.system.VMStack.getThreadStackTrace"),
                    ste.newObject("com.taobao.taobao.main"));
        }
        if (signature.startsWith("java/lang/StackTraceElement->")) {
            String m = signature.substring(signature.indexOf("->") + 2);
            if (m.startsWith("getClassName()") || m.startsWith("getMethodName()")
                    || m.startsWith("getFileName()")) {
                Object v = dvmObject.getValue();
                return new StringObject(vm, v == null ? "" : String.valueOf(v));
            }
            if (m.startsWith("isNativeMethod()")) return DvmBoolean.valueOf(vm, false);
            if (m.startsWith("getLineNumber()")) return DvmInteger.valueOf(vm, 0);
        }
        if (signature.startsWith("com/alibaba/wireless/security/securitybody/SecurityBodyAdapter->doAdapter")) {
            // securitybody 无感风控组件：模拟环境返回空串让主流程继续
            return new StringObject(vm, "");
        }
        // HashMap put/get：value 为真实 Map
        if (signature.startsWith("java/util/HashMap->put(Ljava/lang/Object;Ljava/lang/Object;)")) {
            Object mapObj = dvmObject.getValue();
            if (mapObj instanceof java.util.Map) {
                Object k = varArg.getObjectArg(0), v = varArg.getObjectArg(1);
                String key = k == null ? "" : String.valueOf(((DvmObject) k).getValue());
                String val = v == null ? "" : String.valueOf(((DvmObject) v).getValue());
                System.out.println("[JNI] HashMap.put(" + key + ", len=" + val.length() + ")");
                return new StringObject(vm, String.valueOf(
                        ((java.util.Map<String, Object>) mapObj).put(key, val)));
            }
        }
        if (signature.startsWith("java/util/HashMap->get(Ljava/lang/Object;)")) {
            Object mapObj = dvmObject.getValue();
            if (mapObj instanceof java.util.Map) {
                Object k = varArg.getObjectArg(0);
                String key = k == null ? "" : String.valueOf(((DvmObject) k).getValue());
                Object val = ((java.util.Map<String, Object>) mapObj).get(key);
                return val == null ? null : new StringObject(vm, String.valueOf(val));
            }
        }
        switch (signature) {
            // 与 callObjectMethodV 相同的 Context/File/PM 家族（ARM64 标准调用走非 V 版本）
            case "android/content/Context->getPackageName()Ljava/lang/String;":
            case "android/content/ContextWrapper->getPackageName()Ljava/lang/String;":
            case "android/app/Application->getPackageName()Ljava/lang/String;":
                return new StringObject(vm, PROCESS_NAME);
            case "android/content/Context->getPackageCodePath()Ljava/lang/String;":
            case "android/content/ContextWrapper->getPackageCodePath()Ljava/lang/String;":
                return new StringObject(vm, CODE_PATH);
            case "android/content/Context->getFilesDir()Ljava/io/File;":
            case "android/content/ContextWrapper->getFilesDir()Ljava/io/File;":
                return vm.resolveClass("java/io/File").newObject(DATA_DIR + "/files");
            case "android/content/Context->getCacheDir()Ljava/io/File;":
            case "android/content/ContextWrapper->getCacheDir()Ljava/io/File;":
                return vm.resolveClass("java/io/File").newObject(DATA_DIR + "/cache");
            case "android/content/Context->getDataDir()Ljava/io/File;":
            case "android/content/ContextWrapper->getDataDir()Ljava/io/File;":
                return vm.resolveClass("java/io/File").newObject(DATA_DIR);
            case "android/content/Context->getDir(Ljava/lang/String;I)Ljava/io/File;":
                return vm.resolveClass("java/io/File").newObject(
                        DATA_DIR + "/app_" + varArg.getObjectArg(0).getValue());
            case "android/content/Context->getPackageManager()Landroid/content/pm/PackageManager;":
            case "android/content/ContextWrapper->getPackageManager()Landroid/content/pm/PackageManager;":
                return vm.resolveClass("android/content/pm/PackageManager").newObject(null);
            case "android/content/Context->getApplicationInfo()Landroid/content/pm/ApplicationInfo;":
            case "android/content/ContextWrapper->getApplicationInfo()Landroid/content/pm/ApplicationInfo;":
                return new ApplicationInfo(vm);
            case "android/content/pm/PackageManager->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;":
                return vm.resolveClass("android/content/pm/PackageInfo").newObject(null);
            case "android/content/pm/PackageManager->getInstalledPackages(I)Ljava/util/List;":
                return vm.resolveClass("java/util/ArrayList").newObject(new java.util.ArrayList<DvmObject>());
            case "java/io/File->getAbsolutePath()Ljava/lang/String;":
            case "java/io/File->getPath()Ljava/lang/String;":
                return new StringObject(vm, String.valueOf(dvmObject.getValue()));
            case "java/io/File->exists()Z":
                return DvmBoolean.valueOf(vm, new java.io.File(String.valueOf(dvmObject.getValue())).exists());
            case "java/io/File->mkdirs()Z":
            case "java/io/File->isDirectory()Z":
                return DvmBoolean.valueOf(vm, true);
            case "java/lang/Object->toString()Ljava/lang/String;":
                return new StringObject(vm, String.valueOf(dvmObject.getValue()));
            case "java/util/Map->toString()Ljava/lang/String;":
            case "java/util/HashMap->toString()Ljava/lang/String;":
                return new StringObject(vm, "{}");
            case "java/lang/ClassLoader->loadClass(Ljava/lang/String;)Ljava/lang/Class;":
                return vm.resolveClass(String.valueOf(varArg.getObjectArg(0).getValue())).newObject(null);
            default:
                return super.callObjectMethod(vm, dvmObject, signature, varArg);
        }
    }

    @Override
    public DvmObject callObjectMethodV(BaseVM vm, DvmObject dvmObject, String signature, VaList vaList) {
        // 通用 ClassLoader 获取（V 版本）
        if (signature.endsWith("->getClassLoader()Ljava/lang/ClassLoader;")) {
            return vm.resolveClass("java/lang/ClassLoader").newObject(null);
        }
        switch (signature) {
            // Context 家族（10101 init 会顺 Context 走一圈）
            case "android/content/Context->getPackageName()Ljava/lang/String;":
            case "android/content/ContextWrapper->getPackageName()Ljava/lang/String;":
                return new StringObject(vm, PROCESS_NAME);
            case "android/content/Context->getPackageCodePath()Ljava/lang/String;":
            case "android/content/ContextWrapper->getPackageCodePath()Ljava/lang/String;":
                return new StringObject(vm, CODE_PATH);
            case "android/content/Context->getFilesDir()Ljava/io/File;":
            case "android/content/ContextWrapper->getFilesDir()Ljava/io/File;":
                return vm.resolveClass("java/io/File").newObject(DATA_DIR + "/files");
            case "android/content/Context->getCacheDir()Ljava/io/File;":
            case "android/content/ContextWrapper->getCacheDir()Ljava/io/File;":
                return vm.resolveClass("java/io/File").newObject(DATA_DIR + "/cache");
            case "android/content/Context->getDataDir()Ljava/io/File;":
            case "android/content/ContextWrapper->getDataDir()Ljava/io/File;":
                return vm.resolveClass("java/io/File").newObject(DATA_DIR);
            case "android/content/Context->getDir(Ljava/lang/String;I)Ljava/io/File;":
                return vm.resolveClass("java/io/File").newObject(
                        DATA_DIR + "/app_" + vaList.getObjectArg(0).getValue());
            case "android/content/Context->getPackageManager()Landroid/content/pm/PackageManager;":
            case "android/content/ContextWrapper->getPackageManager()Landroid/content/pm/PackageManager;":
                return vm.resolveClass("android/content/pm/PackageManager").newObject(null);
            case "android/content/Context->getApplicationInfo()Landroid/content/pm/ApplicationInfo;":
            case "android/content/ContextWrapper->getApplicationInfo()Landroid/content/pm/ApplicationInfo;":
                return new ApplicationInfo(vm);
            case "android/content/Context->getSystemService(Ljava/lang/String;)Ljava/lang/Object;":
            case "android/content/ContextWrapper->getSystemService(Ljava/lang/String;)Ljava/lang/Object;":
                return vm.resolveClass("java/lang/Object").newObject(null);
            // PackageManager
            case "android/content/pm/PackageManager->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;":
                return vm.resolveClass("android/content/pm/PackageInfo").newObject(null);
            case "android/content/pm/PackageManager->getInstalledPackages(I)Ljava/util/List;":
                return vm.resolveClass("java/util/ArrayList").newObject(new java.util.ArrayList<DvmObject>());
            // File
            case "java/io/File->getAbsolutePath()Ljava/lang/String;":
            case "java/io/File->getPath()Ljava/lang/String;":
                return new StringObject(vm, String.valueOf(dvmObject.getValue()));
            case "java/io/File->exists()Z":
                return DvmBoolean.valueOf(vm, new java.io.File(String.valueOf(dvmObject.getValue())).exists());
            case "java/io/File->mkdirs()Z":
                return DvmBoolean.valueOf(vm, true);
            case "java/io/File->isDirectory()Z":
                return DvmBoolean.valueOf(vm, true);
            // 原有回调
            case "java/lang/Thread->getStackTrace()[Ljava/lang/StackTraceElement;":
                // 伪造常规 Android 栈，防止 SDK 探测宿主真实 Java 环境
                DvmClass ste = vm.resolveClass("java/lang/StackTraceElement");
                return new ArrayObject(
                        ste.newObject("dalvik.system.VMStack.getThreadStackTrace"),
                        ste.newObject("com.taobao.taobao.main"));
            case "java/lang/StackTraceElement->getClassName()Ljava/lang/String;":
            case "java/lang/StackTraceElement->getMethodName()Ljava/lang/String;":
            case "java/lang/StackTraceElement->getFileName()Ljava/lang/String;":
                Object v = dvmObject.getValue();
                return new StringObject(vm, v == null ? "" : String.valueOf(v));
            case "java/lang/StackTraceElement->isNativeMethod()Z":
                return DvmBoolean.valueOf(vm, false);
            case "java/lang/StackTraceElement->getLineNumber()I":
                return DvmInteger.valueOf(vm, 0);
            case "android/app/Application->getPackageName()Ljava/lang/String;":
                return new StringObject(vm, PROCESS_NAME);
            case "android/content/ContentResolver->call(Landroid/net/Uri;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;":
                return vm.resolveClass("android/os/Bundle").newObject(null);
            case "android/os/Bundle->getString(Ljava/lang/String;)Ljava/lang/String;":
                return new StringObject(vm, "");
            case "android/os/Bundle->getBytes(Ljava/lang/String;)[B":
                return new ByteArray(vm, new byte[0]);
            case "java/net/NetworkInterface->getHardwareAddress()[B":
                return new ByteArray(vm, new byte[]{0, 0, 0, 0, 0, 0});
            default:
                return super.callObjectMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        switch (signature) {
            case "android/app/ApplicationInfo->sourceDir:Ljava/lang/String;":
            case "android/content/pm/ApplicationInfo->sourceDir:Ljava/lang/String;":
            case "android/app/ApplicationInfo->publicSourceDir:Ljava/lang/String;":
            case "android/content/pm/ApplicationInfo->publicSourceDir:Ljava/lang/String;":
            case "android/app/ApplicationInfo->scanSourceDir:Ljava/lang/String;":
            case "android/content/pm/ApplicationInfo->scanSourceDir:Ljava/lang/String;":
                return new StringObject(vm, CODE_PATH);
            case "android/app/ApplicationInfo->dataDir:Ljava/lang/String;":
            case "android/content/pm/ApplicationInfo->dataDir:Ljava/lang/String;":
                return new StringObject(vm, DATA_DIR);
            case "android/app/ApplicationInfo->nativeLibraryDir:Ljava/lang/String;":
            case "android/content/pm/ApplicationInfo->nativeLibraryDir:Ljava/lang/String;":
                return new StringObject(vm, "/data/app/~~9j0QgXp3hA0yWk1VcJ2ZPw==/com.taobao.taobao-VeK8mPqLr2XwYz0aB1cD6e==/lib/arm64");
            case "android/app/ApplicationInfo->nativeLibraryRootDir:Ljava/lang/String;":
            case "android/content/pm/ApplicationInfo->nativeLibraryRootDir:Ljava/lang/String;":
                return new StringObject(vm, "/data/app/~~9j0QgXp3hA0yWk1VcJ2ZPw==/com.taobao.taobao-VeK8mPqLr2XwYz0aB1cD6e==/lib");
            case "android/app/ApplicationInfo->packageName:Ljava/lang/String;":
            case "android/content/pm/ApplicationInfo->packageName:Ljava/lang/String;":
                return new StringObject(vm, PROCESS_NAME);
            case "android/app/ApplicationInfo->processName:Ljava/lang/String;":
            case "android/content/pm/ApplicationInfo->processName:Ljava/lang/String;":
                return new StringObject(vm, PROCESS_NAME);
            case "android/content/pm/PackageInfo->signatures:[Landroid/content/pm/Signature;":
                // 空数组而非 null：SDK 靠字段存在性判断
                return vm.resolveClass("[Landroid/content/pm/Signature;").newObject(
                        new DvmObject[0]);
            case "android/content/pm/PackageInfo->versionName:Ljava/lang/String;":
                return new StringObject(vm, "10.68.0");
            case "android/content/pm/PackageInfo->packageName:Ljava/lang/String;":
                return new StringObject(vm, PROCESS_NAME);
            case "android/content/pm/PackageInfo->versionCode:I":
                return DvmInteger.valueOf(vm, 26800);
            default:
                return super.getObjectField(vm, dvmObject, signature);
        }
    }
}
