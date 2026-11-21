package com.taobao.search.sign;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.taobao.search.vm.TaobaoVM;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * 真实 unidbg 签名后端：模拟 libsgmain 的 SecurityGuard.signRequest。
 *
 * smali 证据 (tb/n9f = mtopsdk.security.InnerSignImpl):
 *   SecurityGuardParamContext.ctx.appKey = appKey
 *   paramMap["INPUT"] = "api&version&appKey&t&data"
 *   ISecureSignatureComponent.signRequest(ctx, authCode) -> mtop_sign
 *
 * 本类提供两条调用路径（与开源 unidbg-server 的 DouyinSignService 一致）:
 *   1) callStaticJniMethodObject 按 JNI 签名调用
 *   2) module.callFunction 按 SO 偏移直接调用（更快，需知道真实偏移）
 * 具体 JNI 签名/偏移需按目标 APP 版本用 verbose JNI 日志确定，见 docs/HOOK_GUIDE.md。
 */
@Component
@ConditionalOnBean(name = "taobaoVM")
public class UnidbgMtopSigner implements MtopSigner {

    private static final Logger log = LoggerFactory.getLogger(UnidbgMtopSigner.class);

    /** 可由配置文件覆盖：真实 SO 里 signRequest 对应函数的偏移 */
    private static final long SIGN_FUNCTION_OFFSET = 0x0L;

    /** JNI 方法签名占位（真实值按 verbose 日志确定） */
    private static final String SIGN_JNI_SIG =
            "(Lcom/alibaba/wireless/security/open/SecurityGuardParamContext;Ljava/lang/String;)Ljava/lang/String;";

    @Autowired(required = false)
    private TaobaoVM taobaoVM;

    @Override
    public String backend() {
        return "unidbg";
    }

    @Override
    public synchronized Map<String, String> sign(String api, String version, String appKey, long t, String data) {
        Map<String, String> result = new HashMap<String, String>();
        if (taobaoVM == null || taobaoVM.getVm() == null) {
            throw new IllegalStateException("unidbg 后端未初始化，请检查 TaobaoSignConfiguration 或改用 signBackend=mock");
        }

        String input = api + "&" + version + "&" + appKey + "&" + t + "&" + data;
        VM vm = taobaoVM.getVm();
        AndroidEmulator emulator = taobaoVM.getEmulator();

        try {
            // 待签串：与 smali 里 paramMap["INPUT"] 一致。
            // 字段注入(appKey/INPUT/requestType)由 TaobaoJni 在构造期拦截 <init>/put 完成。
            log.debug("sign input prepared: api={}, len={}", api, input.length());

            DvmObject<?> signed = null;
            Module module = taobaoVM.getModule();
            DvmClass sgClass = vm.resolveClass(
                    "com/alibaba/wireless/security/open/SecurityGuardParamContext");
            Map<String, String> ctxValue = new HashMap<String, String>();
            ctxValue.put("appKey", appKey);
            ctxValue.put("INPUT", input);
            DvmObject<?> ctx = sgClass.newObject(ctxValue);

            if (module != null && SIGN_FUNCTION_OFFSET > 0) {
                // 路径 2：按 SO 偏移直接调用（快），返回 jstring 的地址
                Number ret = module.callFunction(emulator, SIGN_FUNCTION_OFFSET,
                        vm.getJNIEnv(), ctx, new StringObject(vm, ""));
                if (ret != null) {
                    Object obj = vm.getObject(ret.intValue());
                    if (obj instanceof StringObject) signed = (StringObject) obj;
                }
            } else {
                // 路径 1：按 JNI 方法签名调用（推荐先用 verbose 日志拿到真实签名再填 SIGN_JNI_SIG）
                signed = vm.resolveClass(
                        "com/alibaba/wireless/security/open/securesignature/ISecureSignatureComponent")
                        .callStaticJniMethodObject(emulator, SIGN_JNI_SIG, ctx, new StringObject(vm, ""));
            }

            if (signed != null && signed.getValue() != null) {
                result.put("mtop_sign", signed.getValue().toString());
                result.put("x-sign", signed.getValue().toString());
            } else {
                throw new IllegalStateException("signRequest 返回空，通常意味着 JNI 补环境不完整");
            }
        } catch (Exception e) {
            log.error("unidbg signRequest failed: {}", e.getMessage());
            throw new RuntimeException("unidbg 签名失败: " + e.getMessage(), e);
        }
        return result;
    }
}
