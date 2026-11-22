# 淘宝逆向代码审查与回归报告（2026-11-22）

## 1. 范围与结论

对两套工程做了只读审查 + 全套回归：

- `taobao-search-unidbg`（签名/token 服务，Java SpringBoot + unidbg）
- `taobao-rebuild`（APK smali 重建链 + 通用 skill）

审查用三个独立视角并行（Java 源码 / 构建链脚本 / 测试覆盖），共发现 **40+ 项**，其中已修复 6 项高价值问题，其余按风险分级列在第 4 节供后续处理。

**回归结果：全部通过。**

| 项目 | 结果 |
| --- | --- |
| `mvn package`（含全部单测） | PASS，jar 50M |
| 单测 `SignContextTest` | 4/4 PASS（含新补的真机逐字节 + 边界断言） |
| `e2e_test.sh`（h5/rpc） | 4 项 PASS，sign_reject=0 |
| `e2e_unidbg.sh`（native 签名，严格 native==6） | 2 项 PASS |
| `test_image_upload.sh`（白名单后） | 2 项 PASS，strimg.len=42196 |
| 越界文件读取 `/etc/hosts` | 被拒，网关未收到 strimg（安全修复有效） |

## 2. 已修复（本轮）

| # | 严重度 | 文件 | 问题与修法 |
| --- | --- | --- | --- |
| 1 | High | `jni/TaobaoJni.java:108` | `&&`/`||` 优先级 bug：`(idx>0 && endsWith) || contains` 使条件恒真，且 `idx=0` 时 `substring(0,0)` 空类崩溃。改为显式括号 `idx>0 && (endsWith \|\| contains)` |
| 2 | Medium | `jni/TaobaoJni.java:157` | `SystemClock.elapsedRealtime()` 返回 epoch 墙上时钟而非单调时钟，破坏 SO 内计时/反调试。改用 `System.nanoTime()/1e6` |
| 3 | Medium | `test/SignContextTest.java` | `testDeviceIdLengths` 是自证式断言（只测字面量自身），零覆盖生产代码。改为断言 `buildInput` 实产段长度 |
| 4 | Medium | `test/SignContextTest.java` | 补 `testNullAndSeparatorFields`：覆盖 null 归一化 + `&` 分隔符破坏 22 段的已知限制 |
| 5 | Medium | `tools/e2e_unidbg.sh:91` | 断言只判 `_native_headers` 非零，`=5` 也能混过。改为严格 `==6` 且要求 `_h5_sign=present`，堵住"全绿假象" |
| 6 | **Critical** | `service/ImageSearchService.java` + `application.properties` | `imagePath` 直接 `Files.readAllBytes` 任意路径 → 本地文件被 base64 外发到淘宝网关（配合 `server.address=0.0.0.0` 可被局域网利用）。新增 `image.allowed-dir=/tmp/tb_img` 白名单，`toRealPath()` 后校验 `startsWith` + 普通文件 + ≤10MB |

## 3. 核实后确认"不是 bug"的点（避免误改）

- **appKey 21646297 vs 12574478**：不是配置冲突。真机 ground truth 显示 native 70102 payload 用 `21646297`，H5 MD5 sign 用 `12574478`，两套协议各用各的，当前实现正好匹配。`MTOP_GATEWAY_ACS` 未引用属 app 模式未启用，非回归风险。
- **q vs keyword**：请求参数确为 `q`，与 smali 逆向一致。
- **时间戳单位**：主链路 `currentTimeMillis()/1000`（秒），正确。
- **MD5 编码**：各 signer 均显式 UTF-8，正确。
- **mock 网关 sign 校验**：`md5(token&t&appKey&data)` 与 `H5MtopSigner` 一致，并非任何 sign 都放行。

## 4. 未修复的发现（按风险分级，供后续决策）

### High（影响生产/便携性）
- **H1** `UnidbgMtopSigner.java:33-41`：APK 路径写死 `/Users/liaozetao/...`，SO/totem 用相对 CWD 路径，打成 jar 或换机器即失败。应改配置项 + classpath 读取。
- **H2** `SecurityGuardEngine`：unidbg emulator 无 `destroy()`/`@PreDestroy`，native 内存与线程不释放。
- **H3** `MtopHttpClient:110-111`：token 与 cookie 分两次读取（TOCTOU），并发下 sign 用旧 token、cookie 用新 token → TOKEN_EXPIRED。应提供原子快照。
- **H4** `HumanBehaviorSimulator.rotate()`：设备三要素分别 volatile 写，签名 payload 与 x-* 头可能错位。应封装不可变 `DeviceIdentity` 原子替换。
- **H5** `SignerRouter:27`：默认 `sign-fallback=true` 把后端故障静默降级为 mock，生产排障困难。
- **H6** 全部接口无鉴权 + `0.0.0.0` 监听：局域网可借用出口 IP 注入凭据发请求。

### Medium
- `MtopHttpClient` app 模式 `uid`/`sid` 恒为空，与 sign payload 的 sid 不一致 → 注入登录态时 ILEGAL_SIGN。
- `mtop.protocol=app` 不切换网关，`MTOP_GATEWAY_ACS` 从未使用，仍打 H5 域名。
- `TaobaoJni.java:108` 附近的 `HashMap.put` 有 `System.out.println` 热路径刷屏。
- `SecurityGuardEngine:197` INFO 级打印 payload 前 120 字符（含设备标识），应降 debug。

### 测试覆盖盲区（E2E 全绿但没真验证的部分）
- `e2e_test.sh` 的 `attempts>=1` 恒真（`ApiResponse.ok()` 硬编码 1），握手 trail 只打印不断言。
- mock 网关把错误 sign 标为 `FAIL_SYS_TOKEN_EXPIRED` 而非 ILLEGAL_SIGN，`SIGN_REJECTED` 分支不可达。
- `SignEngineRegression`（直接测 native 签名引擎）无 runner（注释引用的 `tools/regression.sh` 不存在），未纳入 `mvn test`。
- mock 后端、`SIGN_REJECTED`/风控/超时/并发、设备三要素同源一致性均无测试。
- 三脚本默认共用 8099 端口、后台进程 RC 从不检查，存在假阳性/flaky 风险。

### taobao-rebuild / skill（构建链）
- **C1** `build.gradle` 的 `assembleSmali` 无 inputs 又无 `outputs.upToDateWhen{false}`，改了 smali 可能被判 UP-TO-DATE 跳过，装上旧 dex。
- **C2** `verify.py` 只比 dex 的 version/class_count，`dex_facts.size` 算了却没用，无内容哈希，dex 内容篡改可漏过。
- **H** `parallel_download.py` 不校验 `Content-Range`、`ftruncate` 稀疏文件大小恒等于 total 导致成功误判；工程版缺 skill 版已有的小文件越界守卫。
- **H** `signApk` 的 zipalign/apksigner 判据分离，可能用 jarsigner 签已对齐 APK 破坏对齐。
- **M** `repackage.py` 只检查 rebuilt⊆original，不检查原 APK 所有 dex 都被替换，可能新旧 dex 混用。
- **M** `init_project.py` 模板填充无转义（Groovy 注入）、吞掉 keytool 失败、提示引用未复制的 Gradle 路径、写死绝对路径损害可移植性。
- **M** 签名密码 `android` 明文硬编码（调试用途，扩散到所有 skill 生成工程）。
- **L** `verify.py`/`repackage.py` 的 META-INF 签名文件判断口径三处不一致。

## 5. 建议优先级

1. 立即：C1（构建可能装旧 dex）、H1/H2（便携性/资源泄漏）—— 这几项影响正确性或可部署性。
2. 短期：H3/H4（并发签名一致性）、测试盲区加固（握手断言 + native 头值校验）。
3. 按需：C2（内容哈希校验）、app 模式网关切换、鉴权。

本轮已修复的高危项是 #1/#2（JNI 逻辑）和 #6（任意文件读取安全），并已全量回归确认无回归。
