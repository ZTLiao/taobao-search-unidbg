package com.taobao.search.config;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;
import com.taobao.search.jni.TaobaoJni;
import com.taobao.search.vm.TaobaoVM;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.File;

/**
 * 淘宝 unidbg 签名环境配置（对应开源 unidbg-server 的 DouyinConfiguration）。
 *
 * 通过 application.properties 里 unidbg.enabled=true 开启。
 * 默认关闭 => 只用 mock 后端，工程开箱即可跑通链路；开启后走真实 libsgmain 模拟。
 *
 * 注意：libsgmain 是阿里加固 SO，完整补环境工作量很大。本配置提供可运行的骨架，
 * 首次启用需按 HOOK_GUIDE.md 用 verbose JNI 日志补齐 TaobaoJni。
 */
@Configuration
public class TaobaoSignConfiguration {

    private static final Logger log = LoggerFactory.getLogger(TaobaoSignConfiguration.class);

    @Value("${unidbg.apk-path:native/com.taobao.taobao.apk}")
    private String apkPath;

    @Value("${unidbg.so-name:libsgmainso-6.8.261102.so}")
    private String soName;

    @Value("${unidbg.verbose:false}")
    private boolean verbose;

    @Bean(name = "taobaoVM")
    @ConditionalOnProperty(name = "unidbg.enabled", havingValue = "true")
    public TaobaoVM taobaoVM() {
        log.info("初始化 unidbg 模拟器: apk={}, so={}", apkPath, soName);

        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new DynarmicFactory(true))
                .setProcessName(TaobaoJni.PROCESS_NAME)
                .build();

        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        File apk = new File(apkPath);
        VM vm = emulator.createDalvikVM(apk.exists() ? apk : null);
        vm.setJni(new TaobaoJni());
        vm.setVerbose(verbose);

        TaobaoVM holder = new TaobaoVM();
        holder.setEmulator(emulator);
        holder.setVm(vm);

        try {
            File so = findSo(soName);
            if (so != null) {
                DalvikModule dm = vm.loadLibrary(so, true);
                dm.callJNI_OnLoad(emulator);
                holder.setSecguardModule(dm);
                holder.setModule(dm.getModule());
                log.info("SO 已加载: {}", so.getAbsolutePath());
            } else {
                log.warn("未找到 {}, 仅 VM 可用，签名调用会失败", soName);
            }
        } catch (Exception e) {
            log.warn("SO 加载异常（补环境未完成时可忽略）: {}", e.getMessage());
        }
        return holder;
    }

    private File findSo(String name) {
        String[] candidates = {
                "native/arm64-v8a/" + name,
                "src/main/resources/native/arm64-v8a/" + name,
                name
        };
        for (String p : candidates) {
            File f = new File(p);
            if (f.exists()) return f;
        }
        return null;
    }
}
