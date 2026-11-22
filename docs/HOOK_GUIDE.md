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

## 7. 已验证的最终配置（2026-11-22 实测打通）

### 7.1 JNA / Apple Silicon（关键）
- pom `dependencyManagement` 全局锁 `net.java.dev.jna:jna:5.10.0`：
  unidbg 0.9.8 传递的 5.7.0 官方 jar 无 darwin-aarch64 原生库；
  jna_silicon 4.5.2 的原生库(5.2.2)与 5.x Java 类期望版本(6.1.x)不符，不能混搭。
  5.10.0 自带 `darwin-aarch64/libjnidispatch.jnilib`，版本自洽，**无需任何 NativeLoader 预引导**。
- 若保留 `Class.forName("com.sun.jna.NativeLoader")` 预引导反而会注入旧版原生库导致
  `incompatible JNA native library (Expected 6.1.2, Found 5.2.2)`。

### 7.2 unidbg API 差异（0.9.8）
- `DvmInteger/DvmBoolean/DvmLong` 在 `com.github.unidbg.linux.android.dvm.wrapper` 包。
- `VaList/VarArg` 取参：`getIntArg(0)` / `getLongArg(0)` / `getObjectArg(0)`。
- unicorn 后端可用；dynarmic 不支持该 SO 的 AVMP 指令。

### 7.3 必备 JNI 回调（TaobaoJni）
- `SecurityBodyAdapter->doAdapter(I)Ljava/lang/String;`（静态与实例两条路径都返回空串）
- `java/util/HashMap-><init>()V / <init>(I)V`：value 持真实 LinkedHashMap（70102 结果容器）
- `DeviceInfoCapturer->doCommandForString` → 空串；`doCommandForInt` → 0
- `getMainPluginClassLoader/getPluginClassLoader` → ClassLoader 空实例
- SPUtility2 read/save → 内存 KV（SP_STORE）
- init 链 10102→10101→10103→10104，签名 70102（12 参数）→ {x-sign, x-mini-wua, x-sgext, x-umt}

### 7.4 运行
- 启动：`java -jar target/taobao-search-unidbg-1.0.0.jar --unidbg.enabled=true --mtop.gateway=http://127.0.0.1:8099/`
- 首次调用 ~18s（引擎懒加载：SO+JNI_OnLoad+init 链+70102），热调用 ~0.4s。
- 响应 `signMeta._native_headers=6` 表示 native 四头 + H5 MD5 sign 组合签名生效。
- 回归：`bash tools/e2e_test.sh`（4 项断言）；单测探针：`bash tools/probe.sh 70102 unicorn`。

## 8. RGV587 风控拦截：分层诊断与修复方案（2026-11-22 实测）

### 8.1 风控分层结构（实测结论）
| 层 | 拦截特征 | 位置 | 突破条件（已实测） |
|---|---|---|---|
| L1 设备指纹层 | `RGV587_ERROR::SM::哎哟喂被挤爆啦` + TMD 页面 URL + x5secdata cookie | h5api/acs 前置 | **App 协议形态**：POST acs.m.taobao.com/gw/ + App UA + unidbg 四头（x-sign/x-mini-wua/x-sgext/x-umt）+ appKey=21646297 |
| L2 协议参数层 | `FAIL_SYS_PROTOPARAM_MISSED::缺少协议参数` | acs /gw/ | 表单含 api/v/appKey/t/sign/ttid/data/utdid/uid/sid；**禁止携带 x-pv 头**（实测触发 PROTOPARAM_MISSED）；suggest 类接口需 m-pv/m-appkey/m-sign/m-t 头 |
| L3 验证层 | `FAIL_SYS_USER_VALIDATE` + `bxpunish:1 / bx-action:login / bx-retry:true` + Location=punish 页 | bixi 系统 | 需登录态 cookie 或浏览器过 punish 页取 x5sec 注入重试 |
| L3' 协议版本层 | `FAIL_SYS_ACCESS_DENIED::请下载升级最新版本APP` | m-top 新协议 | m-pv=8.1.0 + m-appkey + m-t 通过完整性校验，但 m-sign 新算法未实现（下一步：逆向新版 mtopsdk m-sign 或真机抓包对照） |

### 8.2 工程已实现的能力（mtop.protocol=app）
- `MtopHttpClient` App 协议模式：POST form-only + MTOPSDK UA + x-t/x-app-ver/x-features/x-utdid/x-c-traceid + unidbg 四头，sign 位放 x-sign。
- 风控分类：USER_VALIDATE(bx-action=login) / RGV587::SM(设备指纹) 分开提示；`ApiResponse.punishUrl` 提取 Location 头 punish 页。
- Cookie 注入通道：`POST /api/token {"cookie":"x5sec=...; cna=..."}`（请求自动携带，网关下发的 x5secdata 也被 jar 自动吸收）。

### 8.3 剩余缺口与路径
1. **登录态/验证**（L3）：注入真机登录 cookie（cookie2/unb/sktrack 或 sid/uid）→ 直接可达业务数据；或浏览器打开 punishUrl 完成验证取 x5sec。
2. **m-sign 新签名算法**（L3'）：suggest 等接口要求新版协议头族（m-pv/m-appkey/m-sign/m-t），m-sign 为新算法，需逆向新版 mtopsdk 组装逻辑（smali: MtopBusiness/protocol param builder）或真机抓包逐字段对照。
3. **指纹保真度**：x-umt 当前全零（umid 未采集）；DeviceInfoCapturer 返回空串——补真实设备数据可提高 L1/L3 通过率。

## 9. ILEGAL_SIGN 根因修复：native payload 必须是真机 15 段 INPUT（2026-11-22）

### 9.1 情报核实（纠正一处误传）
网上流传「native 签名需要 32 位 token，与 _m_h5_tk 同源」——**这是混淆了两套协议**：
- Gitee `kuqoi/x-sign` 里的 32 位 `token` 是**第三方签名服务 api.xsign.com 的私有 API key**（原文「联系 QQ 申请」），不是淘宝协议字段。
- 32 位 `_m_h5_tk` 只用于 **H5 网关** `sign=MD5(token&t&appKey&data)`，**不参与 App native x-sign**。
- App native x-sign 的 INPUT **首字段是 utdid（24 位）**，不是 token。三个独立 hook 来源交叉验证一致：
  - sechub.in（天猫精灵）：`utdId&uid&&appkey&hashvalue&t&api&1.0&sid&ttid&deviceId&&&extdata&27&&&&&&&`
  - code84.com（淘宝 9.23）：`{utdid}&{uid}&&{appkey}&...`
  - 本项目 Frida hook `tb.n9f.f`（10.68）：`utdid&uid&reqbiz-ext&appKey&md5(data)&t&api&v&sid&ttid&deviceId&lat&lng&extdata&x-features&7空位`
- mtopsdk 取 token 的 API：`InnerSignImpl.getMtopApiSign(HashMap, appKey, authCode)` → `SecurityGuardManager.getSecureSignatureComp().signRequest(SecurityGuardParamContext{appKey, requestType=7, paramMap}, authCode)`。底层 smali `tb/n9f` L1440-1636 拼装上述 INPUT；**没有单独的「native 32 位 token 获取 API」**。

### 9.2 真正的根因
`SecurityGuardEngine.sign()` 旧实现（**❌ 错误示范，切勿复制；当前生产实现已改用 `SignContext.buildInput()`**）：
```java
// ❌ 已被修复：仅 3 段 + 硬编码 utdid，会触发 FAIL_SYS_ILLEGAL_SIGN。
// 仅 SgProbe 的 JNI 链路自检 / SecurityGuardEngine 的 @Deprecated 兼容重载仍保留此写法，
// 二者都不可用于真实网关请求。正确实现见 9.3 节与 SignContext.java。
String payload = "at88wsLQ2wUDACdd6tSLBrZ7&&&" + appKey + "&&&";
```
两个致命问题：
1. payload 只有 3 段，缺 md5/t/api/v/sid/ttid/deviceId/lat/lng/extdata/x-features。
2. 签名 payload 里 utdid 硬编码，但 HTTP 头 `x-utdid` 用 `human.sessionUtdid()` 随机值——**签名与请求头 utdid 不一致 → FAIL_SYS_ILLEGAL_SIGN**。

### 9.3 修复内容
- 新增 `sign/SignContext.java`：封装 utdid/deviceId/sid/uid/ttid/extdata/xFeatures/lat/lng，`buildInput()` 按真机顺序拼 15 段 + 7 空位。
- `SecurityGuardEngine.sign()` 新增带 `(t, SignContext)` 重载，用 `md5(data)` 和完整 INPUT 作 70102 payload（保留旧重载仅作链路自检）。
- `HumanBehaviorSimulator` 设备身份升级为**会话级稳定三要素**：utdid=24 位、deviceId=44 位、sid=32 位（可 BYO 注入）；生成长度与真机一致。
- `MtopHttpClient` 构造 SignContext 并透传到签名层；`x-utdid`/`x-devid`/`x-sid` 头与签名 payload **共用同一组值**。
- `application.properties` 新增 `mtop.utdid` / `mtop.device-id` / `mtop.sid` 注入项（真机抓包值可大幅提升通过率）。
- 新增 `SignContextTest` 单测验证 15 段结构与字段位置。

### 9.4 验证
- `mvn -Dtest=SignContextTest test` PASS，生成 INPUT 与公开真机格式逐字段一致。
- `bash tools/e2e_test.sh` 4 项断言全 PASS，无回归。

## 10. 真机 70102 ground truth（Frida hook 淘宝 10.69.10，2026-11-22）

### 10.1 突破 native hook 参数解析
之前 native hook 卡在 `access violation accessing 0x558`，根因是 `jniFn()` 多解引用了一层：
- 正确：`env.readPointer()` 得到 JNIEnv vtable 基址，再 `.add(index*8).readPointer()` 取函数指针。
- 错误：`env.readPointer().readPointer()` 把第 0 项函数指针的值当基址，得到垃圾地址。

修正后用 `JNICLibrary.doCommandNative` 的 JNI 层 hook（vtable 索引 GetArrayLength=171 / GetObjectArrayElement=173 / GetStringUTFChars=169）成功 dump 出 70102 的完整 12 参数与返回值。可用脚本：`tools/frida/hook_full_bundle.js`（esbuild 打包的 frida-java-bridge + native dump，bundle 已内含 bridge，Frida 17 直接 `-l` 加载即可）。

### 10.2 真机 INPUT（决定性证据）
hook 到的 `doCommandNative(70102, args)` 中 `args[1]` 原文：
```
awJISchpPiMDADAJ3weNXszG&&&21646297&f8f124264d8437ae645551f73b3e5047&1795313584&mtop.taobao.wireless.home.newface.awesome.get&1.0&&231200@taobao_android_10.69.10&Aiw8S8YGCUMNCOMAFfPJIdq-Pyb4740VtErxvLS58KdE&37.42195&-122.084013&openappkey=DEFAULT_AUTH&27&&&&&&&
```
共 22 段（15 有效字段 + 7 空位），与 `SignContext.buildInput()` 输出**逐字节一致**（单测 `testRealDeviceGroundTruth` 固化）。这彻底验证第 9 章 payload 修复正确。

字段确认：utdid(24) / uid(空) / reqbiz-ext(空) / appKey / md5(data) / t(秒) / api / v / sid(空) / ttid(`231200@taobao_android_10.69.10`) / deviceId(44) / lat / lng / extdata(`openappkey=DEFAULT_AUTH`) / x-features(27) / 7空位。
- `md5(data)` = `tb/g8p.b()`（SecurityUtils.getMd5，utf-8），smali 静态分析与真机值吻合。
- 真机返回头除 x-sign/x-sgext/x-umt/x-mini-wua 外还有 **x-gst**（新头，可选）。

### 10.3 m-sign 结论（重要）
真机 10.69.10 的 native 签名仍走标准 15 段 INPUT + x-* 头族，**APP 本身不产生 m-sign/m-pv/m-appkey 头族**。之前真网关索要 m-sign（`FAIL_SYS_PROTOPARAM_MISSED::缺少协议参数m-sign`）是请求形态触发了服务端的新协议分支，不是本 APP 版本的协议。用本 APK/unidbg 无法凭空算出 m-sign——需拿到要求 m-pv=8.1.0 的新版 APP 样本再 hook 其内层参数构造器，或改用官方开放平台 API。
