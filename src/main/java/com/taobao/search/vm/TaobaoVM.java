package com.taobao.search.vm;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.VM;

/**
 * 淘宝 unidbg 模拟器容器（对应开源 unidbg-server 的 DouyinVM）。
 * 持有 emulator / vm / secguard module，供签名 Service 复用单例，避免重复加载 SO。
 */
public class TaobaoVM {
    private AndroidEmulator emulator;
    private VM vm;
    private DalvikModule secguardModule;
    private Module module;

    public AndroidEmulator getEmulator() { return emulator; }
    public void setEmulator(AndroidEmulator emulator) { this.emulator = emulator; }
    public VM getVm() { return vm; }
    public void setVm(VM vm) { this.vm = vm; }
    public DalvikModule getSecguardModule() { return secguardModule; }
    public void setSecguardModule(DalvikModule secguardModule) { this.secguardModule = secguardModule; }
    public Module getModule() { return module; }
    public void setModule(Module module) { this.module = module; }
}
