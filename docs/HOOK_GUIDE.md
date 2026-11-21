# unidbg 补环境指南（开启真实签名）

本工程的 `unidbg` 签名后端复刻开源 unidbg-server 的扩展方式，但目标 SO 换成了淘宝的 `libsgmain`（阿里 SecurityGuard）。这类 SO 是加固/强混淆库，完整补环境工作量远大于普通 SO。本指南说明如何推进。

## 1.  honor 前提

- **本工程默认 `signBackend=mock`**，开箱即可跑通全链路（参数→签名占位→网关→解析）。
- 真实请求淘宝网关需要有效的 `_m_h5_tk` token + 合法 mtop_sign + 设备指纹，这些依赖正确的 SO 签名。
- unidbg 模拟 libsgmain 属于逆向研究的高阶环节，能否成功取决于目标 APP 版本与补环境完整度。

## 2. 开启 unidbg 后端

`application.properties`：
```properties
unidbg.enabled=true
unidbg.verbose=true          # 关键：打印每一条 JNI 调用
search.sign-backend=unidbg
```

把 APK 放到 `native/com.taobao.taobao.apk`（92M，故意不打包进 jar，从外部读取）：
```bash
cp ../app/com.taobao.taobao.apk src/main/resources/native/com.taobao.taobao.apk
# 或放到工程运行目录下的 native/
```

SO 已放在 `src/main/resources/native/arm64-v8a/`。

## 3. 补环境迭代流程（核心）

1. 用 `unidbg.verbose=true` 启动，签名调用会在第一条未补的 JNI 处抛异常，日志形如：
   ```
   JNIEnv->CallStaticObjectMethodV(...) java/lang/xxx->yyy(...)
   ```
2. 把这条 signature 原样加进 `jni/TaobaoJni.java` 对应的 `call*MethodV` switch，返回合理值：
   - 返回 String：`new StringObject(vm, "...")`
   - 返回设备信息：伪造 utdid/imei/android_id
   - 返回 Class/Object：`vm.resolveClass("...").newObject(...)`
3. 重新 `mvn package` 并重启，看下一个未补的 JNI，重复直到 `signRequest` 返回非空的 `mtop_sign`。
4. 对照真机抓包（Frida hook `ISecureSignatureComponent.signRequest` 的入参/出参）校验 unidbg 输出是否一致。

参考开源 unidbg-server 的 `DouyinJniNext.java`（本工程 `_upstream_unidbg-server` 有下载副本）就是这种"逐条补 JNI"的范例。

## 4. 两条调用路径

`sign/UnidbgMtopSigner` 提供：
- **路径 1（默认）**：`callStaticJniMethodObject` 按 JNI 方法签名调用。需先用 verbose 日志拿到真实签名填入 `SIGN_JNI_SIG`。
- **路径 2（快）**：`module.callFunction(emulator, offset, ...)` 按 SO 函数偏移直接调用。用 IDA/Ghidra 定位 `signRequest` 对应函数地址填入 `SIGN_FUNCTION_OFFSET`。

## 5. 常见问题

- `Failed to resolve JNI method`：JNI 签名字符串不对，从 verbose 日志复制原文。
- 返回空 sign：JNI 补环境不完整，继续按第 3 步补。
- `dynarmic` backend 报错：改用 `Unicorn` backend（去掉 `.addBackendFactory(new DynarmicFactory(true))`），速度慢但兼容性好。
- SO 加载即崩溃：可能是 64 位 SO 用了 `for64Bit()`，确认 ABI 与 SO 一致（本工程按 arm64-v8a）。

## 6. 降级策略

`search.sign-fallback=true` 时，unidbg 签名失败会自动降级到 mock 并在响应里带 `_fallback_reason`，保证服务不中断，便于观察是哪里补环境失败。
