package com.taobao.search.config;

import com.taobao.search.vm.TaobaoVM;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 淘宝 unidbg 签名环境配置。
 *
 * unidbg.enabled=true 时启用。真实模拟在 SecurityGuardEngine 中（懒加载单例）：
 *   - 加载 libsgmainso-6.8.261102.so（unicorn 后端，dynarmic 不兼容该 SO 的 AVMP 指令）
 *   - JNI_OnLoad -> RegisterNatives(JNICLibrary.doCommandNative)
 *   - init 链 10102/10101/10103/10104 -> 签名 70102
 * 详细迭代过程见 docs/HOOK_GUIDE.md。
 */
@Configuration
public class TaobaoSignConfiguration {

    private static final Logger log = LoggerFactory.getLogger(TaobaoSignConfiguration.class);

    static {
        // JNA 已统一为 5.10.0（自带 darwin-aarch64 原生库），无需 NativeLoader 预引导。
    }

    @Bean(name = "taobaoVM")
    @ConditionalOnProperty(name = "unidbg.enabled", havingValue = "true")
    public TaobaoVM taobaoVM() {
        log.info("unidbg 签名后端启用（SecurityGuardEngine 懒加载，unicorn 后端）");
        return new TaobaoVM();
    }
}
