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

## 11. 真机搜索接口定位 + 未登录证据（Frida hook buildParams，2026-11-22）

### 11.1 黄金 hook 点
`mtopsdk.mtop.protocol.builder.impl.InnerProtocolParamBuilderImpl.buildParams(Ltb/w4j;)Ljava/util/Map;`
是 mtopsdk 生成全部协议参数的入口。hook 它可一次拿到：api 名、data、appKey、ttid、utdid、umt、全部公共参数。
- Frida 的 `console.log(String(map.get(k)))` 会截断到 ~200 字符；用 `send()` 分片发送可拿完整 data。
- 脚本：`tools/frida/hook_bp.js`（基于 hook_full_bundle.js，已修 data 分片）。

### 11.2 决定性发现：搜索接口选错了
真机统一搜索页（`com.taobao.search.uniform.SearchActivity`）**不调用** `mtop.taobao.wsearch.appsearch`。
3 次 hook（不同关键词）捕获的真实搜索主接口：
```
api   = mtop.relationrecommend.MtopRecommend.recommend  (v1.0)
data  = {"active_bd":"1","appId":"66","areaCode":"CN","brand":"google",
         "bxFeature":"{\"TT\":1,\"data\":[],\"error_code\":20807,...}",
         "isEnterSrpSearch":"true","n":"10","page":"1","q":"wireless mouse",
         "requestAlias":"wsearch","style":"list","ttid":"231200@taobao_android_10.69.10",
         "utd_id":"awJWVNCcPKUDAL7ibHrmB9O4","vm":"nw", ...}   // 共 903 字符
```
并发还有 `WirelessRecommend.recommend`(appId=33378)、`mtoprecommend.recommend`(appId=30219, code=duplex_pre_connect_init)、`mtop.common.getTimestamp`。
- 核心区分字段：`requestAlias=wsearch` / `isEnterSrpSearch=true` / `appId=66` / `q=关键词`。
- `appsearch` 是老接口，服务端把未登录请求引导到登录墙（`FAIL_SYS_USER_VALIDATE`）；真机新接口可出数据。

### 11.3 真机公共参数模板（未登录场景，全部实测）
```
nq=3G  x-features=27  x-app-conf-v=0  appKey=21646297
umt=WiUB/mFLPG4qQgKiATYHzKeUIk+Xea2m  f-refer=mtop  utdid=<24位>
netType=HSPA  x-app-ver=10.69.10  extdata=openappkey=DEFAULT_AUTH
x-c-traceid=x-falco-id=<8位随机如7fKhyLJS>  ttid=231200@taobao_android_10.69.10
x-page-url=taobao://s.taobao.com/search  x-page-name=com.taobao.search.uniform.SearchActivity
user-agent=MTOPSDK/3.1.1.7 (Android;15;Google;sdk_gphone64_arm64) DeviceType(Phone)
```
MtopNetworkProp 额外：`bizId=89  bizTopic=main-all  openAppKey=DEFAULT_AUTH  openTraceContext={x-ctx-bag__scene=MainSearch_FirstScreen}`

### 11.4 决定性证据：真机完全未登录仍能出数据
dump 搜索主接口的 MtopNetworkProp + CookieManager：
```
accessToken=null  authCode=null  reqUserId=null  userInfo=DEFAULT
requestHeaders=null  requestSourceAppKey=null
COOKIE s.taobao.com = null  useCache=false
```
→ 真机**无登录态、无 Cookie、无 token、不走缓存**仍渲染出真实商品（截图 docs/real_iphone18_search.png）。
之前"搜索接口强制登录"的结论**被推翻**：服务端拦的是未通过设备态校验的伪造请求，不是登录本身。

### 11.5 代码改动
- `TaobaoConstants` 新增 `API_TEXT_SEARCH_NATIVE = mtop.relationrecommend.MtopRecommend.recommend`。
- `TextSearchService`：`mtop.protocol=app` 时用真机接口 + 真机 data 结构（`nativeSearchData()`）；h5/mock 保留老结构。
- `MtopHttpClient` app 模式补齐全部真机公共头/参数（x-app-conf-v/x-c-traceid/x-falco-id/x-page-name/x-page-url/f-refer/netType/nq/umt）。
- `HumanBehaviorSimulator` 新增 sessionUmt()/appUa()/traceId()/app-conf-v，支持 BYO 注入 `mtop.umt`。
- `application.properties` 新增 `mtop.umt` / `mtop.app-conf-v`。

### 11.6 实测结果与根因收敛
切到真机接口 + 真机身份后，真实 acs 网关**仍返回 FAIL_SYS_USER_VALIDATE**。但 signMeta 显示四头已带（`_native_headers=6`），70102 payload 与真机格式一致。
- 根因收敛到：native 四头（尤其 `x-mini-wua` / `x-sgext`）里嵌入的**设备运行时环境特征**过不了服务端设备态校验。真机 libsgmain 在真实设备上生成，服务端可验证；unidbg 模拟环境生成的 wua/sgext 环境特征不匹配。
- 真机 `bxFeature.error_code=20807`（bixi SDK 本地报错）仍能出数据 → 商品数据来自更上层客户端能力（推荐流/缓存降级），不是单靠 HTTP x-sign。
- **结论**：纯 HTTP + unidbg 签名复刻真机未登录搜索，在当前证据下走不通。要拿真实数据仍需：① 自持登录 Cookie（系统已支持 POST /api/token）；② 官方开放平台 API；③ 真机 RPC 签名服务（把真机 signRequest 作为 sign.rpc.url 后端，让四头来自真机）。
- 回归：mvn test 全过、主 E2E 4 项 PASS、unidbg E2E 2 项 PASS，无回归。

## 12. 真机 signRequest → Frida RPC 签名后端（2026-11-22）

### 12.1 交付内容
| 文件 | 作用 |
|---|---|
| `tools/frida/rpc_sign.js` | Frida 脚本源码；`rpc.exports` 暴露 `signRequest / signSdk / signByInner / signExact / signLegacy / deviceInfo / status / lastCapture` |
| `tools/frida/build_rpc_bundle.py` | 复用 `hook_full_bundle.js` 里已打包的 frida-java-bridge，生成可独立加载的 `rpc_sign_bundle.js`（Frida 17 已不内置 `Java`） |
| `tools/frida_rpc_bridge.py` | HTTP 桥接服务：`POST /api/sign`（RpcMtopSigner 直接可用）、`/api/sign/legacy`、`/api/sign/sdk`、`/api/sign/exact`、`GET /health`、`/device`、`/capture`、`/debug/<rpcName>` |
| `tools/probe_frida_rpc.py` | 冒烟探针：attach/spawn 后打印 status、device、各签名接口结果 |
| `RpcMtopSigner.java` | 透传 `SignContext` 与按真机 22 段格式拼好的 `input`；可选从 `/device` 自动同步真机 utdid/deviceId/umt |
| `HumanBehaviorSimulator.java` | 新增 `adoptRemoteDevice(...)`，让签名 payload 与 x-utdid/x-devid/x-umt 同源 |

启动：
```bash
python3 tools/frida/build_rpc_bundle.py
python3 tools/frida_rpc_bridge.py --port 9091     # 默认 attach 主进程
# 若 Frida 只列出 :channel 进程，可用 adb shell pidof com.taobao.taobao 取 PID：
FRIDA_PID=<主进程PID> python3 tools/frida_rpc_bridge.py --port 9091
# 需要从启动阶段 hook：
FRIDA_SPAWN=1 python3 tools/frida_rpc_bridge.py --port 9091
```
工程侧：
```bash
--search.sign-backend=rpc --sign.rpc.url=http://127.0.0.1:9091/api/sign
--mtop.protocol=app --mtop.gateway=https://acs.m.taobao.com/gw/
--mtop.app-key=21646297 --mtop.ttid=231200@taobao_android_10.69.10
```

### 12.2 运行时发现（重要，避免重复踩坑）
在模拟器 Android 15 / 淘宝 10.69.10 上实测：

1. `Java.choose('tb/n9f')` 能找到 6 个 `InnerSignImpl` 实例，但 `f`（`IUnifiedSecurityComponent`）与 `a`（MtopConfig）字段经 Frida 读到的都是 `null`；`c`（SecurityGuardManager）可读。
2. `com.alibaba.wireless.security.open...` 的 `getSecurityFactors` / 两参 `signRequest` 以及 `com.taobao.wireless.security.sdk...` 的一参 `signRequest`，都能从真机组件对象上调到，但返回 `SecException`（message 为空）或空串——组件未在本进程完成 middle-tier 初始化，主动 `init()` 后仍失败。
3. SecurityGuard 类由插件 ClassLoader 加载，默认 `Java.use` 会抛 `ClassNotFoundException`；脚本里用 `Java.enumerateClassLoadersSync()` + `Java.ClassFactory.get(loader)` 解决，`JNICLibrary` hook 因此可用。
4. 搜索期间 `JNICLibrary.doCommandNative` 实际命令为 `70603/20801/13801/12611/70101/70103` 等；**未观测到 70102**（早期 70102 ground truth 来自另一注入时机/版本）。
5. `tb/n9f.f(Map,String,boolean)` 可稳定产出真机 INPUT，例如：
   `awJWVNCcPKUDAL7ibHrmB9O4&&&21646297&ecca9b00a...&1795318141&mtop.relationrecommend.mtoprecommend.recommend&1.0&&231200@taobao_android_10.69.10&&&&openappkey=DEFAULT_AUTH&27&&&&&&&`
   说明 Java 层仍有完整的参数拼装能力，四头的最终产出点在本版本走的是另一条 native 路径。
6. `buildParams` 抓到真机搜索主接口为 `mtop.relationrecommend.mtoprecommend.recommend`（小写 mtoprecommend），与项目已配置的 `MtopRecommend.recommend` 不一致，后续对接时应以抓包值为准。

**结论**：RPC 后端骨架与 HTTP 协议已打通并回归通过；但在当前这台模拟器/App 版本上，上述 Java 签名入口拿不到可用四头，`POST /api/sign` 会返回 `SecException`。要拿到真实四头，需继续定位本版本真正产出 `x-*` 的 native 入口（建议从 `SecretUtil` / middletier plugin 的 RegisterNatives 反查），或改用能稳定触发 70102 的 App 版本/注入时机。工程侧 mock E2E（`backend=rpc`）仍全 PASS，未引入回归。

## 13. 彻底打通尝试：四头产出路径排除 + 环境根因（2026-11-22 下午）

### 13.1 本轮结论（重要，避免继续无效循环）
在模拟器 Android 15 / 淘宝 10.69.10 上，用 deeplink 与真实 UI 两种触发方式、注入/不注入 Frida 多种组合反复实测，得到三条决定性结论：

1. **真机搜索请求的 `buildParams` 返回 Map 里没有 `x-sign`/`x-mini-wua`/`x-sgext`/`sign`**。完整键为：
   `nq/data/deviceId/sid/uid/x-features/x-app-conf-v/appKey/api/umt/f-refer/utdid/netType/x-app-ver/extdata/x-c-traceid/ttid/t/v/x-falco-id/x-page-url/x-page-name/user-agent`。
   其中 `umt`（UMID 设备态 token，如 `qDAB/NZLPNRUEgKiASBAdlHAivDtXDIF`）才是本版本搜索的核心设备凭据。
2. **本版本搜索接口 `tb/n9f.r()` 返回 null**（入参 `useWua=false`，data 是 `{"appId":"33378","params":"{\"devLevel\":\"high\"}"}` 设备探测），即搜索请求本身**不生成传统 WUA 四头**。smali 侧 `InnerNetworkConverter.getHeaderConversionMap()` 虽注册了 `x-sign←sign`，但 buildParams 返回值无 `sign` 源。
3. **当前模拟器环境自身无法成功搜索**：无论是否注入 Frida、deeplink 还是 UI 输入，搜索统一返回错误页 `FEC40002`（底层 `getTaobaoWuaToken -> SecException` 持续刷屏）。这是环境问题（清数据后 UC WebView `NOT_SUPPORT_ARCH:qemu` + 风控），与项目代码/Frida hook 无关。

由此排除第 12 章遗留的“继续反查 native 四头入口”方向：**本版本搜索不走 x-sign 四头，攻四头是错的方向**。

### 13.2 RPC 后端现状（可用部分）
`POST /api/sign/mtop` 已能稳定返回真机 `buildParams` 的完整设备态参数，并支持覆盖 `api/version/data` 后由 App 现场重签（`_changed` 标记改写成功）。`/device` 可持续同步真机 `umt/utdid/ttid`，`RpcMtopSigner.syncDevice` 已接入，工程侧 app 模式请求已补齐 umt/nq/netType/x-c-traceid 等真机公共参数。这部分链路完整可用。

### 13.3 脚本加固（本轮代码改动）
`tools/frida/rpc_sign.js`：
- **禁用** `install70102Hook()` / `installNative70102Dump()`：二者对高频 `doCommandNative` 做 JNI dump，触发大量 JNI 异常并导致淘宝进程重启（实测 PID 频繁变化）。禁用后进程稳定。
- `buildParams` hook 现保存完整返回 Map（`buildParamsOut`）、真机请求上下文（`requestCtx`），并快照四头/设备字段。
- 新增被动捕获：`netUrlLog`（网络栈 URL 诊断）、`headerCapture`（HttpURLConnection 的 x-* 头）、`netHeaders`（OkHttp/ANetwork 头）。实测真机 MTOP 请求不走这三种 Java 网络 API（anetwork 栈抓到的 mtopsdk 请求走 native），故这些捕获为空——进一步印证四头/签名在 native 层。
- 新增 `signByMtop`（复用真机 buildParams 改写字段重签）、`replaySuccess`（用成功 r() 入参重放）、`successSign` 等导出。
- **警告**：`signExact`（主动调 `getSecurityFactors`）、`signByInner`（主动调 `r()`）在本版本会触发 `SecException` 并导致进程崩溃，实测多次；`signByInner` 强制 useWua=true 亦返回 null。主动签名入口一律不可用。

### 13.4 后续可行路径（收敛）
真机 RPC 后端要产出服务端认可的签名，只剩两条：
1. **换能稳定触发 70102 的环境/App 版本**（旧版淘宝或真机非模拟器），从 native `doCommandNative(70102)` 拿四头；本版本搜索不用四头，此路对本版本无意义。
2. **自持登录 Cookie 或官方开放平台 API**：绕开设备态风控校验。
3. 若目标是复刻本版本搜索请求：直接复用 `buildParams` 返回的真机参数（含 umt）+ H5 token MD5 sign，而非 native 四头——但需服务端认可该设备态 token，当前模拟器环境 FEC40002 无法验证。

回归：`mvn -DskipTests package` / `mvn test`（真机 INPUT 逐字节断言）/ `tools/e2e_test.sh`（4 项含 rpc 后端）全 PASS，无回归。

### 13.5 换环境验证结论：必须用真机（2026-11-22）
- 本机只有 qemu 模拟器（Android 15 arm64），无真机。用原版 APK 干净重装淘宝后首页商品流恢复，但搜索结果页 / 登录页渲染为黑屏，logcat：`ucbs.Setup: u4 init failed / NOT_SUPPORT_ARCH: qemu`。
- 根因：搜索结果页依赖 UC WebView（u4），而 UC WebView 不支持 qemu 架构。故"真机 UI 搜索成功并抓四头"这条路在 qemu 模拟器上根本走不通，与 Frida/代码/风控无关。
- 要完成真实网关端到端验证，需接入真实 Android 手机（USB 或 network adb）。接入后可复用现成流程：
  ```bash
  adb devices   # 确认真机 serial
  FRIDA_PID=$(adb shell pidof com.taobao.taobao) python3 tools/frida_rpc_bridge.py --port 9091
  # UI 或 deeplink 触发搜索 -> /debug/headerCapture、/debug/buildParamsOut 抓真实请求
  ```

---

## 14. 真机接入实测：签名后端打通 + m-pv/m-sign 方向证伪（2026-11-22 下午）

用户接入真机 `cb76b262`（TrebleDroid vanilla / tdgsi_arm64_ab，Android 13 / API 33 / arm64 / USB，`ro.kernel.qemu` 为空=真机），原版淘宝 10.69.10 干净安装。

### 14.1 真机环境准备（可复现步骤）
```bash
export PATH="/Users/liaozetao/.local/android/sdk/platform-tools:$PATH"
adb -s cb76b262 root                    # userdebug GSI 支持 adb root
adb -s cb76b262 push ~/.local/android/frida/frida-server /data/local/tmp/frida-server
adb -s cb76b262 shell chmod 755 /data/local/tmp/frida-server
adb -s cb76b262 shell 'nohup /data/local/tmp/frida-server -D >/data/local/tmp/frida.log 2>&1 &'
# frida 客户端 17.27.4（~/.workbuddy/binaries/python/versions/3.13.12/bin/python3）
FRIDA_DEVICE=cb76b262 python3 tools/frida_rpc_bridge.py --port 9091
```
- 真机 frida-server 需 root；注意 `adb unroot` 后 frida-server 会退出、且淘宝仍检测到 su（见 14.4）。
- 探针脚本：`tools/probe_real_device.py`（spawn 注入 + 触发搜索 + dump ground truth）、`tools/probe_sign_active.py`（主动签名）。

### 14.2 决定性突破：真机四头签名后端完全可用（推翻第13章"不可用"结论）
第13章在 qemu 上 `rSuccessCount=0`、主动签名全 SecException，判定四头路径不可用。**真机上完全相反**：
- `rCallCount=12 / rSuccessCount=12`，`tb/n9f.r()` 稳定产出完整四头：`x-sign`/`x-mini-wua`/`x-sgext`/`x-umt`/`x-gst`/`wua`/`sign`。
- 70102 INPUT ground truth（f() 返回，22 段）与本项目 `SignContext.buildInput()` 逐字段一致：
  ```
  awJ3hY/Mq3EDAMWt0Bs6MAqV&&&21646297&6923524365c8f7e38eb96c4ab6dd55ad&1795324047&mtop.guge.guangguang.redpoint&1.0&&231200@taobao_android_10.69.10&AuBCx84bur5HR28RMM72yrJz4vwoHvSvwGKrf56_wj6j&&&openappkey=DEFAULT_AUTH&27&&&&&&&
  ```
- **核心能力**：`signByMtop`（`tools/frida/rpc_sign.js` 的 `signByMtop()`，复用真机 MtopRequest 上下文调 `buildParams`）可对**任意 api/data** 产真机签名，`_changed.api/version/data` 全 true，data 注入后 sign 随之变化（签名与 data 绑定）。桥接 `/api/sign` 首选此路径，实测返回真机 `sign`/`x-mini-wua`/`x-sgext`/`x-gst`/`umt`，`_rpc_backend=frida-real-device`。
- 真机设备身份：utdid=`awJ3hY/Mq3EDAMWt0Bs6MAqV`、deviceId=`AuBCx84bur5HR28RMM72yrJz4vwoHvSvwGKrf56_wj6j`(44位)、umt=`nQkBd8pLPL4NaAKiAeNTMq1rozOWT26L`(32位)、ttid=`231200@taobao_android_10.69.10`。

### 14.3 两个确定性 bug 修复（本轮代码改动）
1. **RpcMtopSigner fastjson 展开陷阱**：原 `jo.getJSONObject("data")` 会把真机桥接回显的「搜索 data 字符串」（合法 JSON 文本）隐式解析成 JSONObject，导致 payload 被错当成搜索参数、丢失 sign/x-* 字段 → 抛"未返回有效签名字段"→ 静默降级 mock。修复为先判定 `jo.get("data") instanceof JSONObject` 才展开。修复后 signMeta 只剩 `_rpc`/`_rpc_backend`，RPC 签名被真实采纳。
2. **设备身份不同步**：`adoptRemoteDevice` 之前不同步 ttid，导致签名 INPUT 第9段/data.ttid 用旧 `taobao@android_10.28.0`，而真机签名后端内嵌 `231200@taobao_android_10.69.10`。新增 `HumanBehaviorSimulator.sessionTtid/sessionAppUa` + `effectiveTtid()`，MtopHttpClient（SignContext/form/header）与 TextSearchService（data.ttid）统一取同步值。

### 14.4 真机端到端正向数据验证：环境级阻塞（非代码 bug）
- **root 检测**：这台是 TrebleDroid userdebug GSI，自带 su。淘宝 AuthSDK 报 `600005 手机终端不安全:the phone is root, Device has su!`。即使 `adb unroot`，su 仍在系统里 → 登录墙 `BX_RETRY` → scheme 搜索 iphone18 一直骨架屏、UI 点击搜索框直接跳 UserLoginActivity。**真机 UI 搜索在此环境也拿不到数据**，需非 root 的普通量产机。
- **首页正常**：真机首页商品流完整渲染（FILA/Swisse/百亿补贴等），证明 UC WebView 黑屏是 qemu 专属（第13章），真机无此问题。
- **网关协议分支**：用 rpc 真机签名 + app 协议 + 真实网关 `acs.m.taobao.com/gw/` 请求搜索，网关返回 `FAIL_SYS_PROTOVER_MISSED::缺少协议版本m-pv`。

### 14.5 m-pv/m-sign 方向证伪（Frida hook Map.put 实测）
`tools/frida/hook_msign_probe.js`（打包为 `hook_msign_probe_bundle.js`）hook `HashMap/LinkedHashMap/ArrayMap.put` 抓真机搜索请求头族，结果：
- 真机 App 10.69.10 搜索**只发** `x-sign`、`pv=6.3`、`x-pv=6.3`；
- **完全不发** `m-pv`/`m-sign`/`m-appkey`/`m-t`。
- 结论坐实第8章：m-pv/m-sign 是**网关对我们请求形态的判定分支**，不是真机 App 协议；继续逆 m-sign 算法是错方向。要过这一层需让请求形态与真机一致（真实设备态/登录 Cookie），或走官方开放平台。

### 14.6 回归
- `mvn test` PASS（SignContextTest 真机 INPUT 逐字节断言）。
- `e2e_test.sh` 4 项 PASS（text/suggest/image/rpc，sign_reject=0）。
- `e2e_unidbg.sh` 2 项 PASS（nativeHeaders=6）。
- 结论：真机签名后端 + 两个 bug 修复全部落地且无回归；剩余阻塞为环境（root 检测）与服务端协议判定（m-pv 分支），非可修复代码缺陷。

---

## 15. m-pv/m-sign 协议层攻破：不要逆算法，构造头族即可（2026-11-22 晚，决定性）

第 14.5 节"逆 m-sign 是错方向"的判断**方向对但不彻底**：m-pv/m-sign 确实不是本 APP 协议，但网关对**我们的请求形态**强制索要这套头族，而这套头族是**可构造的**，无需逆向任何新算法。

### 15.1 网关形态对照实验（`tools/gateway_matrix.py`，真机签名 + 真实网关）
系统测试 api 大小写 / pv / x-pv / 四头位置 / GET-POST / x-gst / m-* 头族，逐层推进：
| 请求形态 | 网关返回 | 结论 |
|---|---|---|
| 基线（无 m-* 头） | `FAIL_SYS_PROTOVER_MISSED::缺少协议版本m-pv` | m-pv 是**强制协议门槛**，与 x-sign 真伪无关 |
| + `pv=6.3`(form) / 四头放 form / GET / x-gst / api 大小写 | 仍 `PROTOVER_MISSED` | 这些变量全无关 |
| + `x-pv=6.3` 头 | `FAIL_SYS_PROTOPARAM_MISSED` + bx=1 | x-pv 触发另一分支，非正解 |
| + `m-pv=8.1.0` 单头 | `FAIL_SYS_PROTOPARAM_MISSED::缺少协议参数m-...` | 需 m-* 头族齐全 |
| + `m-pv` + `m-appkey` + `m-sign` + `m-t=1` | `FAIL_SYS_REQUEST_EXPIRED::请求失效` | **协议版本层已突破**；m-t=1 过期 |
| + m-* 齐全 + `m-t=<真实秒级时间戳>` | `FAIL_SYS_USER_VALIDATE::登陆成功后请点击重试`（bx-action=login） | **协议层彻底穿越，只剩登录态** |

### 15.2 m-sign 算法无需逆向（`tools/msign_crack.py` 决定性结论）
- `m-t` 必须是**当前秒级时间戳**（固定值 1/0 → REQUEST_EXPIRED；±120s 窗口均接受）。
- `m-sign` 的**内容完全不敏感**：实测 `x-sign`、`"x"`、空串、任意 MD5、`x-mini-wua` 全部同样返回 `USER_VALIDATE`。即服务端在 m-t 有效期内**不校验 m-sign 内容**，只要头存在。
- 结论：m-sign 新算法是**伪命题**——构造头族 + 正确 m-t 即可过协议层，根本不需要逆向。

### 15.3 代码修复（`MtopHttpClient` app 模式）
app 模式新增四个 header：
```java
headers.put("m-pv", "8.1.0");        // 值不敏感
headers.put("m-appkey", appKey);     // 与 form.appKey 一致
headers.put("m-sign", pickSign(sign)); // 内容不敏感，非空即可
headers.put("m-t", String.valueOf(t)); // 关键：当前秒级时间戳
```
修复后用 Java 工程 + 真机 RPC 签名 + 真实网关实测：返回从 `PROTOVER_MISSED` 稳定变为 `USER_VALIDATE`（gatewayRet=RISK_CONTROL，signMeta 仅 `_rpc`/`_rpc_backend`，无 mock 降级）。

### 15.4 最终剩余阻塞：登录态（非代码问题）
- 期望从真机 WebView Cookie DB 提取可用登录 cookie，实测只有一条游客态 `x5secdata`（214B，.taobao.com），注入后仍 `USER_VALIDATE`——过期/会话绑定，无效。
- 真机是 userdebug GSI（自带 su），淘宝 AuthSDK 600005 拒绝登录，UI 也无法产出登录态。
- **要拿真实搜索数据，唯一剩余条件是注入一份有效登录 Cookie**：`POST /api/token {"cookie":"cookie2=...; unb=...; _m_h5_tk=..."}`。协议层（x-sign 四头 + m-* 头族）已全部打通，注入后可直接复用。

### 15.5 本轮新增工具/回归
- 工具：`tools/gateway_matrix.py`（形态对照）、`tools/msign_crack.py`（m-sign 探测）。
- 回归：`mvn test`、`e2e_test.sh`、`e2e_unidbg.sh` 全 PASS（m-* 头族仅在 app+真实网关路径生效，mock/E2E 不受影响）。

---

## 16. 图片搜索 iphone18 回归实测：签名层 NEED_SESSION 硬门槛（2026-11-22 晚）

### 16.1 测试资产与链路
- 图片：`/tmp/tb_img/iphone18.jpg`（Unsplash iPhone 三摄背面，800x1200，39KB）→ base64 进 `strimg`。
- 接口：`mtop.relationrecommend.PailitaoRecommend.recommend` v1.0（smali `PailitaoRecommendRequest.smali` 确认，data 走 `{"params":"{...}","appId":"32969"}` 外层封装）。
- 工具：`tools/probe_image_search.py`（一体化：attach 真机 → signByMtop → 立即发网关，带自动重启重试，规避 userdebug GSI 的 `vendor.oppo.har` SIGABRT 崩溃窗口）。

### 16.2 关键诊断（交叉实验，真机签名）
用同一套 signByMtop + m-* 头族，交叉测试 api 名 / data / session：
| 变量 | 结果 |
|---|---|
| 文本api(小写 mtoprecommend) + 任意 data | `FAIL_SYS_USER_VALIDATE`（签名被认可，到达登录层）|
| 图片api(PailitaoRecommend) + 任意 data | `FAIL_SYS_ILEGEL_SIGN`（签名层直接拒绝）|
| 图片data 从 `{}` 到 53KB 全量 strimg | 全部 ILEGEL_SIGN（与 data 长度无关）|
| 图片api 各种大小写变体 | 只有 PailitaoRecommend 存在，其余 API_NOT_FOUND；存在的都 ILEGEL_SIGN |
| 注入 sid/uid 假值 | 返回 sid 仍空，仍 ILEGEL_SIGN |

### 16.3 根因（smali 决定性证据）
`PailitaoRecommendRequest.smali` 构造函数：`NEED_SESSION = true`（`const/4 v0, 0x1` → NEED_SESSION）。
- 文本搜索接口 `NEED_SESSION=false` → 游客态签名可过 → 到期到 USER_VALIDATE（登录层）。
- 图片搜索接口 `NEED_SESSION=true` → 签名 INPUT 必须含真机**已登录 session**（sid/uid）；未登录时签名被判非法 → ILEGEL_SIGN。
- `signByMtop` 复用真机 MtopRequest 上下文，其 session 来自 App 登录态，无法通过外部 ctx 注入假 sid 伪造。

### 16.4 结论
图片搜索与文本搜索的**最终阻塞是同一个：真机登录态**。
- 文本接口：签名能过 → 网关业务层要求登录（USER_VALIDATE）。
- 图片接口：签名就需要登录 session → 签名层拒绝（ILEGEL_SIGN）。
- 真机是 userdebug GSI（自带 su），AuthSDK 600005 拒绝登录，UI 拍立淘也跳 UserLoginActivity，无法产出登录态。
- 协议层（x-sign 四头 + m-* 头族）对两个接口都已打通；**注入一份有效登录 Cookie 后，两个接口均可复用现有链路**。

### 16.5 回归状态
- 代码未改动（本轮为验证 + 工具/文档）。
- `tools/probe_image_search.py` 可直接复测：`python3 tools/probe_image_search.py --image /tmp/tb_img/iphone18.jpg --q iphone18`。
- 之前 m-* 头族修复的 `mvn test`/`e2e_test.sh`/`e2e_unidbg.sh` 回归仍全 PASS。

## 17. 免登录图片搜索路径探测：推翻第16章 NEED_SESSION 结论（2026-11-22 深夜）

用户诉求：找一条**不需要登录**的图片搜索方式。本轮系统性证伪了第16章"图片接口签名层强制登录"的结论。

### 17.1 决定性证伪：ILEGEL_SIGN 根因是 data 封装，不是 session

第16章断言"图片 API 因 `NEED_SESSION=true` 签名层就需要登录 session，未登录 → ILEGEL_SIGN"。**此结论错误**。

反证链：
1. 反编译全量扫描（`taobao-rebuild/smali-src`，10.3 万 smali）发现：显式 `NEED_SESSION=true` 的只有 `scancode` 包那个**旧** `PailitaoRecommendRequest`；真正的拍立淘 SDK 主路径 `ImageSearchMtopUtil.p()/j() → tb/u7j.a()` 用**同一个 API**，构造的是普通 `MtopRequest`，`needSession` 默认 false，从不 set。
2. 第16章所有 ILEGEL_SIGN 实验用的 data 都是**平铺**结构（`{"region":...,"strimg":...,"appId":"32969"}`）；而文档 16.1 自己和真机 SDK 都记录真机 data 是**外层封装** `{"params":"{...}","appId":"32969"}`。这是从未测过的变量。
3. 决定性实验（`tools/probe_image_search.py --wrapped`，真机 signByMtop + 外层封装）：网关返回从 `FAIL_SYS_ILEGEL_SIGN` **直接变为** `FAIL_SYS_USER_VALIDATE::登陆成功后请点击重试`——和文本接口完全同层。

**结论**：ILEGEL_SIGN 是 data 封装不对导致的签名 INPUT 不匹配，与登录态无关。当前 `ImageSearchService.buildParams()` 用的是平铺结构（第16章 legacy），这是待修的真实 bug。

### 17.2 交叉对照：文本/图片、真机/Mac 出口全部同一结果

`tools/probe_image_ondevice.py`（Frida 内 `signByMtop` 拿真机签名 + 真机 `HttpURLConnection` 从真机网络出口发请求）：
| 接口 | 出口 | 结果 |
|---|---|---|
| 图片 PailitaoRecommend | Mac IP | USER_VALIDATE (wh_ttid=pc) |
| 图片 PailitaoRecommend | **真机 IP** | USER_VALIDATE (wh_ttid=pc) |
| 文本 MtopRecommend | Mac IP | USER_VALIDATE |
| 文本 MtopRecommend | **真机 IP** | USER_VALIDATE |

dump 真机签名字段：`uid="" sid=""`——**真机本身也未登录**，但设备态（utdid/deviceId/umt/ttid）完整。由此排除：登录态本身、出口 IP、接口种类三个变量。**唯一剩余差异：手工构造的 HTTP form 请求被 bixi 识别为 web/PC 形态（`wh_ttid=pc`），走 web 风控；真机 App 原生请求走 anetwork 栈，不经过这层。**

### 17.3 决定性证据：真机原生栈游客态图搜成功（免登录可行）

`tools/probe_image_native.py`：Frida 内拿真机 `Mtop` 实例（`instanceId=INNER`）+ `MtopBuilder.asyncRequest()` 原生发图搜请求，dump 所有 `tb/w4j` 上下文发现一条真机缓存响应：
```
api=mtop.relationrecommend.PailitaoRecommend.recommend
ret=[SUCCESS::调用成功]
data={"failure":"false","result":{"ext":{"taoColor":"dark","bgImgUrl":"https://gw.alicdn.com/..."...
```
即**真机未登录（uid/sid 空）时，原生协议栈确实拿到了真实图搜商品数据**。证明：不需要登录的图搜方式客观存在，卡点不在账号，而在"请求形态必须是 App 原生栈"。

### 17.4 免登录可行路径排序

1. **真机原生 MtopBuilder 发请求**（已证明可达）：Frida 内复用真机 `Mtop` 实例 + `MtopBuilder` 走 anetwork，游客态出数据。工程待办：`MtopBuilder.$new(mtop, mreq, ttid)` 时复用真机 request 改字段会触发 `ANDROID_SYS_MTOPCONTEXT_INIT_ERROR`（Mtop SDK 二次转换），需解决合法 MtopRequest 构造（建议用 `MtopConvert.inputDoToMtopRequest(IMTOPDataObject)` 或真机现成 IMTOPDataObject 类）。
2. **真机 UI 直接搜**（需非 root 量产机）：当前真机是 userdebug GSI 自带 su，AuthSDK 600005 拒绝登录组件，但游客态图搜本身可行；换非 root 量产机后 UI 拍立淘可直接出数据。
3. **注入登录 Cookie**（`POST /api/token`）：绕过 bixi web 风控，但依赖自持有效 cookie，非"免登录"。

### 17.5 本轮新增/改动
- 新增 `tools/probe_h5_image.py`：H5 网关游客态矩阵（本机 IP 全部 RGV587 设备指纹风控，H5 纯 HTTP 路径不通）。
- 新增 `tools/probe_image_ondevice.py`：真机网络出口发请求（图/文 × Mac/真机 交叉对照）。
- 新增 `tools/probe_image_native.py`：真机原生 MtopBuilder 发请求 + w4j 响应 dump。
- 改 `tools/probe_image_search.py`：加 `--wrapped`（外层封装）+ `DUMP_SIGN` 诊断 + form 用真机设备态。
- 待修代码 bug：`ImageSearchService.buildParams()` 应将 data 改为 `{"params":"{...}","appId":"32969"}` 外层封装（本轮未改，避免影响已回归通过的 mock/E2E，下轮单独处理并回归）。

### 17.6 代码修复：data 外层封装（本轮已改 + 回归全绿）
- `ImageSearchService.buildParams()`：`return p`（平铺）改为 `return {"params": JSON.toJSONString(p), "appId": "32969"}`（外层封装），加 `com.alibaba.fastjson.JSON` import。这是真机 SDK ground truth 形态，修正 ILEGEL_SIGN 的数据侧根因。
- `tools/mock_gateway.py`：图片 data 解析兼容外层封装（`if "params" in biz: biz = json.loads(biz["params"])`），保持平铺兼容。
- 回归全绿：`mvn test`（SignContextTest 逐字节断言 PASS）、`tools/test_image_upload.sh`（两种上传 PASS，网关实证 strimg.len=42196，imageUploads=2，sign_reject=0）、`tools/e2e_test.sh`（5 success, sign_reject=0）、`tools/e2e_unidbg.sh`（text+image PASS, nativeHeaders=6；70102 payload md5 已变为外层封装 JSON 的 md5）。

## 18. 免登录原生搜索栈固化（2026-11-22 深夜，用户选择"固化原生免登录栈到代码"）

### 18.1 决定性技术突破：MtopBuilder 重载 bug（此前 INIT_ERROR 的真正根因）

第17章遗留的 `ANDROID_SYS_MTOPCONTEXT_INIT_ERROR`（apiName=null）根因终于定位：
`MtopBuilder` 有 **6 个构造重载**，其中两个三参构造：
- `<init>(Mtop, Object, String)`  —— **deprecated**，内部调 `MtopConvert.inputDoToMtopRequest(Object)` 用反射把对象当 IMTOPDataObject 转换
- `<init>(Mtop, MtopRequest, String)` —— 正确的

Frida 的 `MB.$new(mtop, mreq, ttid)` 会匹配到 `Object` 重载（因为 MtopRequest 也是 Object），
导致 mreq 被错误转换 → apiName 丢失 → INIT_ERROR。
**修复**：显式 `MB.$new.overload('mtopsdk.mtop.intf.Mtop','mtopsdk.mtop.domain.MtopRequest','java.lang.String').call(MB, mtop, mreq, ttid)`。

配套修复：
- 图片大 data 用 `reqMethod(MethodEnum.POST)` + `allowSwitchToPOST(true)`，避免 base64 塞 URL 触发 414。
- 用 `syncRequest()` 同步拿 MtopResponse，替代轮询 w4j（更干净、无缓存串扰）。

修复后原生请求**真实发出**（拿到 Tengine + EagleEye TraceId 的真实响应），证明链路可达。

### 18.2 bixi 是最后一道服务端墙（诚实结论）

原生栈 + 游客态发请求，图片/文本最终都返回 `FAIL_SYS_USER_VALIDATE / ANDROID_SYS_API_41X_ANTI_ATTACK`
（`bx-action=login`，punish 页）。这是**服务端风控环境状态**，非项目代码缺陷：
- 用户截图证明未登录文本搜索**能**出真实数据（iPhone 17 商品列表），说明风控允许时刻确实可达；
- 高频测试会把模拟器打进 `CheckCodeValidateActivity` / "您的账户正在被保护中" 冷却页；
- 当前模拟器（userdebug/已 root + 高频请求）处于冷却期，稳定返回 USER_VALIDATE。

**免登录客观可行，卡点在服务端风控时机，不在登录账号本身，也不在请求形态。**

### 18.3 落地代码（三层调用链）

1. **Frida 层** `tools/frida/rpc_sign.js` 新增 `nativeSearch` export（用 App 的 Mtop 实例 +
   MtopBuilder overload + POST + syncRequest），`build_rpc_bundle.py` 重建进 bundle。
2. **Bridge 层** `tools/frida_rpc_bridge.py`：
   - 新增 `POST /api/search/native` 路由（body: `{api,version,data,ttid,method,headers}`）；
   - `rpc()` 改用 `exports_sync`（Frida 17 异步 exports 对阻塞式 syncRequest 会错乱）；
   - **关键稳定性修复**：不再把缓存的 `_state['pid']` 当 override 传回 connect（淘宝重启后旧 PID 失效会永久卡死），
     改为每次自动 resolve 当前 PID，失败时 disconnect 后用新 PID 重试一次；
   - message handler 加 try/except 防御性日志。
3. **Java 层**：
   - 新增 `service/NativeSearchClient.java`：调 bridge `/api/search/native`，
     映射 retCode/ret/data 成 ApiResponse，注入诊断 `requestStack=app-native-anetwork`、`session=guest-no-login`；
   - `TextSearchService` / `ImageSearchService`：当 `mtop.protocol=native` 且 client 已配置时，
     data 用真机完整结构（文本含 bxFeature error_code=20807；图片外层封装 params+appId），
     分别走 GET/POST，**绕过 MtopHttpClient 手工 HTTP form**。
   - `application.properties` 新增 `sign.rpc.native-search-url`（默认空）。

### 18.4 启动方式与开关

```bash
# 1) 启动 frida bridge（attach 模拟器/真机淘宝）
python3 tools/frida_rpc_bridge.py --port 9091
# 2) 启动 SpringBoot 原生模式
java -jar target/taobao-search-unidbg-1.0.0.jar \
  --mtop.protocol=native \
  --sign.rpc.native-search-url=http://127.0.0.1:9091/api/search/native
```
- `mtop.protocol=native` 开启；h5/app 模式完全不受影响（默认仍 h5）。
- 风控允许时出真实数据；冷却期返回 RISK_CONTROL + 可操作 hint（等冷却或注入 x5sec/cookie）。

### 18.5 回归结果（全绿）

- `mvn test`：SignContextTest 逐字节断言 PASS。
- `tools/e2e_test.sh`（默认 h5）：6 req / 5 success / sign_reject=0 / imageUploads=1（无回归）。
- `tools/e2e_native.sh`（新增，原生模式）：文本 + 图片均返回完整 ApiResponse，
  `signBackend=native+frida-real-device`、`gatewayRet=RISK_CONTROL`、`tokenState=guest`、
  signMeta 五字段齐全（instanceId=INNER/retCode/reqApi/requestStack/session）；
  连续 3 次调用稳定、bridge 全程存活。

### 18.6 待办（可选增强）
- 换非 root 量产机 / 等风控冷却后，用 `tools/capture_ui_search.py` 抓未登录 UI 真实凭证，
  对比后补充 x5sec/cookie 注入，争取在风控允许窗口稳定出真实商品数据。
- `nativeSearch` 里 Mtop 实例选择目前回退顺序 `''/INNER/taobao/21646297`，
  冷启动瞬间可能选到非主实例（曾见 MTOP_ID_ELEME）；建议按 package 主进程 instanceId 精确匹配。
