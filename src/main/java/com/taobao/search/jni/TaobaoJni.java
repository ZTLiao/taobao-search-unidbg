package com.taobao.search.jni;

import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.api.ApplicationInfo;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;

/**
 * SecurityGuard (libsgmain) 补环境 JNI。
 * 复刻开源 unidbg-server 的 DouyinJniNext 写法：对 SO 回调上来的 Java 方法逐一补返回值。
 * 真实工程需根据 vm.setVerbose(true) 打印的 JNI 调用序列持续补充 case。
 */
public class TaobaoJni extends AbstractJni {

    public static final String PROCESS_NAME = "com.taobao.taobao";
    public static final String APK_PATH = "native/com.taobao.taobao.apk";

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
            default:
                return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
        }
    }

    @Override
    public DvmObject callObjectMethodV(BaseVM vm, DvmObject dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "java/lang/Thread->getStackTrace()[Ljava/lang/StackTraceElement;":
                StackTraceElement[] elements = Thread.currentThread().getStackTrace();
                DvmObject[] objs = new DvmObject[elements.length];
                for (int i = 0; i < elements.length; i++) {
                    objs[i] = vm.resolveClass("java/lang/StackTraceElement").newObject(elements[i]);
                }
                return new ArrayObject(objs);
            case "java/lang/StackTraceElement->getClassName()Ljava/lang/String;":
                return new StringObject(vm, ((StackTraceElement) dvmObject.getValue()).getClassName());
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
        if ("android/app/ApplicationInfo->sourceDir:Ljava/lang/String;".equals(signature)
                || "android/content/pm/ApplicationInfo->sourceDir:Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, APK_PATH);
        }
        return super.getObjectField(vm, dvmObject, signature);
    }
}
