# taobao-search-unidbg

以开源 **[unidbg-server](https://github.com/cxapython/unidbg-server)**（SpringBoot 运行 unidbg 的经典骨架）为基础开发的独立工程，用于：

1. 直接接口搜索（文本关键词）
2. 传图识别（拍立淘 / 以图搜图）
3. 返回结构化响应结果
4. 模拟人类操作请求（UA / 设备指纹 / 请求头 / 时序抖动，会话级稳定 utdid）
5. **自动获取有效签名 token**：标准 H5 握手闭环（`_m_h5_tk` → `MD5(token&t&appKey&data)` → 带 Cookie 重发）
6. 可插拔签名后端：`h5`（默认，自动握手）/ `rpc`（自建真机签名服务）/ `unidbg`（补环境）/ `mock`（离线）

配套文档：
- 链路逆向：[`docs/CHAIN_ANALYSIS.md`](docs/CHAIN_ANALYSIS.md)
- **token 握手与打通**：[`docs/TOKEN_HANDSHAKE.md`](docs/TOKEN_HANDSHAKE.md)
- unidbg 补环境：[`docs/HOOK_GUIDE.md`](docs/HOOK_GUIDE.md)

---

## 一、这是什么 / 不是什么

- ❌ 不是「用 unidbg 整体模拟设备跑完图片搜索流程」。图片搜索是 Java 业务层 + 网络层的完整链路，unidbg 只能模拟其中的 native 函数。
- ❌ 不提供风控绕过。网关 `RGV587_ERROR`（滑块/设备/账号校验）属于反自动化对抗，与签名无关，工程会如实分类为 `RISK_CONTROL`。
- ✅ unidbg / rpc 的定位：**提供 app 私有 `x-sign` 签名来源**（由你自持的真机或签名服务产生）。
- ✅ H5 网关的**有效 token 由协议握手自动获取**，不是从 APK 里静态抠出来的常量——这是本版本打通链路的关键。
- ✅ 工程把「签名」与「请求编排」解耦：SpringBoot 负责参数组装 / 会话 / HTTP / 解析，签名后端可插拔。

> 两套签名别混用：H5 网关用 `sign = MD5(token&t&appKey&data)`；app 网关 `acs.m.taobao.com/gw/` 用 native `x-sign`。详见 TOKEN_HANDSHAKE.md。

## 二、目录结构

```
taobao-search-unidbg/
├── pom.xml                         # 基于 unidbg-server 改造（unidbg 0.9.8, fastjson, 阿里云仓库）
├── tools/
│   ├── maven/                      # 内置 Maven 3.9.9（免安装）
│   ├── settings.xml                # 阿里云镜像
│   ├── mock_gateway.py             # 本地 MTOP 网关：完整模拟 H5 token 握手 + sign 校验
│   ├── mock_sign_rpc.py            # 模拟 unidbg-server 签名服务（验证 rpc 后端）
│   └── e2e_test.sh                 # 一键端到端验证（网关+签名服务+服务+断言）
├── src/main/java/com/taobao/search/
│   ├── TaobaoSearchApplication.java
│   ├── config/
│   │   ├── TaobaoConstants.java    # 从 smali 逆向的 API/常量 + H5 token 常量
│   │   └── TaobaoSignConfiguration.java  # emulator+VM+加载 SO（对应 DouyinConfiguration）
│   ├── vm/TaobaoVM.java            # 对应 DouyinVM
│   ├── jni/TaobaoJni.java          # SecurityGuard 补环境 JNI（对应 DouyinJniNext）
│   ├── sign/
│   │   ├── MtopSigner.java         # 签名接口（含带 token 的重载）
│   │   ├── MtopTokenManager.java   # ★ Cookie 会话 / _m_h5_tk 解析 / BYO 注入
│   │   ├── H5MtopSigner.java       # ★ 标准 H5 MD5 签名
│   │   ├── RpcMtopSigner.java      # ★ 转发到自建 unidbg-server / 真机签名服务
│   │   ├── UnidbgMtopSigner.java   # 真实 unidbg 签名（对应 DouyinSignService）
│   │   ├── MockMtopSigner.java     # 离线 mock
│   │   └── SignerRouter.java       # h5/rpc/unidbg/mock 路由 + 降级
│   ├── service/
│   │   ├── MtopHttpClient.java     # ★ 请求构造 + token 握手重试闭环 + 响应诊断
│   │   ├── HumanBehaviorSimulator.java
│   │   ├── TextSearchService.java
│   │   └── ImageSearchService.java
│   ├── controller/                 # /api/... + /api/token 管理端点
│   └── model/                      # DTO（含 token/cookie 注入字段、诊断字段）
├── src/main/resources/
│   ├── application.properties
│   └── native/arm64-v8a/           # libsgmain.so + libsgmainso-6.8.261102.so（从 APK 提取）
└── docs/
```

## 三、构建与运行

环境：JDK 8（Corretto）+ 内置 Maven，无需系统安装。

```bash
cd taobao-search-unidbg
export JAVA_HOME=/Users/liaozetao/Library/Java/JavaVirtualMachines/corretto-1.8.0_452/Contents/HOME
export PATH=$JAVA_HOME/bin:$PATH

./tools/maven/bin/mvn -s tools/settings.xml -DskipTests package
java -jar target/taobao-search-unidbg-1.0.0.jar
```

默认 `search.sign-backend=h5`，启动后首次请求会自动完成 token 握手。

```bash
curl http://127.0.0.1:9090/api/health     # 概览 + token 会话状态
curl -X POST http://127.0.0.1:9090/api/token/handshake   # 主动握手，看轨迹
```

## 四、API 用法

### 1. 文本搜索
```bash
curl -X POST http://127.0.0.1:9090/api/search \
  -H 'Content-Type: application/json' \
  -d '{"q":"连衣裙","page":1,"pageSize":20,"human":true}'
```

### 2. 搜索联想词
```bash
curl 'http://127.0.0.1:9090/api/suggest?q=%E8%BF%9E%E8%A1%A3%E8%A3%99'
```

### 3. 图片搜索（公网 URL / base64 / 本地路径）
```bash
curl -X POST http://127.0.0.1:9090/api/image_search \
  -H 'Content-Type: application/json' -d '{"imageUrl":"https://.../a.jpg"}'

curl -X POST http://127.0.0.1:9090/api/image_search/path \
  -H 'Content-Type: application/json' -d '{"imagePath":"/path/to/shirt.jpg"}'
```

### 4. 注入自持凭据 / 管理 token
```bash
# 请求体内单次注入
curl -X POST http://127.0.0.1:9090/api/search -H 'Content-Type: application/json' \
  -d '{"q":"连衣裙","token":"<你的token>","cookie":"_m_h5_tk=...; ..."}'

curl http://127.0.0.1:9090/api/token                       # 查看状态
curl -X POST http://127.0.0.1:9090/api/token \
  -H 'Content-Type: application/json' -d '{"token":"...","cookie":"..."}'   # 注入
curl -X POST http://127.0.0.1:9090/api/token \
  -H 'Content-Type: application/json' -d '{"refresh":true}'                 # 作废+轮换设备
```

`signBackend` 可用 `"h5"` / `"rpc"` / `"unidbg"` / `"mock"` 单次覆盖全局配置。

### 响应结构（含链路诊断）
```json
{
  "success": true,
  "api": "mtop.taobao.wsearch.appsearch",
  "ret": "SUCCESS::调用成功",
  "signBackend": "h5",
  "requestUrl": "https://h5api.m.taobao.com/h5/...",
  "rawData": { "resultList": ["..."] },
  "items": [ { "itemId": "...", "title": "...", "price": "..." } ],
  "error": null,
  "gatewayRet": "SUCCESS",
  "tokenState": "handshake",
  "attempts": 2,
  "hint": null,
  "handshakeTrail": ["attempt#1 ret=TOKEN_REQUIRED tokenUpdated=true token=present",
                     "attempt#2 ret=SUCCESS tokenUpdated=false token=present"],
  "signMeta": { "_h5_sign": "true", "_token_used": "present" }
}
```

`gatewayRet` 取值：`SUCCESS` / `TOKEN_REQUIRED` / `SIGN_REJECTED` / `RISK_CONTROL` / `LOCAL_ERROR` / `FAIL`；失败时 `hint` 给出可操作建议。排错见 TOKEN_HANDSHAKE.md 第 7 节。

## 五、端到端验证（推荐，一键复现握手闭环）

```bash
bash tools/e2e_test.sh
```

脚本会：启动本地 mock 网关（`_m_h5_tk` 下发 + sign 校验）+ 模拟签名服务 → 启动 SpringBoot → 主动握手 → 依次调用三个接口（h5）与一个 rpc 后端请求 → 断言 `success/gatewayRet/tokenState/items/signBackend`。预期输出：

```
attempt#1 ret=TOKEN_REQUIRED tokenUpdated=true token=present
attempt#2 ret=SUCCESS        tokenUpdated=false token=present
PASS text_search / suggest / image_search / rpc_search    E2E_RESULT=PASS
```

也可手动联调：

```bash
python3 tools/mock_gateway.py 8099 &                     # 终端 1
java -jar target/taobao-search-unidbg-1.0.0.jar \
  --mtop.gateway=http://127.0.0.1:8099/ &               # 终端 2
curl -X POST http://127.0.0.1:9090/api/search \
  -H 'Content-Type: application/json' -d '{"q":"连衣裙","human":false}'   # 终端 3
```

## 六、签名后端切换

| 后端 | 配置 | 说明 |
|---|---|---|
| `h5` | `search.sign-backend=h5` | 默认。自动握手获取 token + 标准 MD5 sign |
| `rpc` | `search.sign-backend=rpc` + `sign.rpc.url=http://.../api/sign` | 对接自建 unidbg-server / 真机 frida-rpc，拿 `x-sign` |
| `unidbg` | `unidbg.enabled=true` + `search.sign-backend=unidbg` | 本地补环境，需按 [`docs/HOOK_GUIDE.md`](docs/HOOK_GUIDE.md) 用 verbose 日志逐条补 `TaobaoJni` |
| `mock` | `search.sign-backend=mock` | 离线占位 / 降级 |

`search.sign-fallback=true` 时，任一后端异常自动降级到 `mock`，并在 `signMeta._fallback_reason` 记录原因。

## 七、验证记录

### 2026-11-22（token 握手打通）
- 新增 6 个类 / 24 个 class，`mvn package` 成功（jar 49M）。
- **本地 mock 网关 E2E**：`E2E_RESULT=PASS`（4 项断言）；握手轨迹 `TOKEN_REQUIRED → SUCCESS`，三个接口 + `rpc` 后端请求均 `success:true` 并解析出商品列表；网关统计 `challenge=1, success=5, sign_reject=0`。`rpc` 后端由 `tools/mock_sign_rpc.py` 模拟 unidbg-server 验证，`signMeta._rpc` 记录签名源。
- **真实网关探测**：`/api/token/handshake` 自动获取有效 `_m_h5_tk`（`source=handshake`，Cookie 含 `_tb_token_/t/cookie2/_m_h5_tk_enc/_m_h5_tk`），第 2 次请求 `SUCCESS` —— **协议层握手在生产环境验证通过**。
- 真实网关业务接口 `search` / `image_search` 返回 `RGV587_ERROR`，被正确分类为 `RISK_CONTROL`（风控层，非签名层）。本工程不提供风控绕过；生产用途建议走官方开放平台 API，或注入自持设备/账号凭据。

### 2026-11-21（初版）
- 完成首页文本搜索 / 拍立淘图片搜索的 smali 链路梳理，搭建 SpringBoot 工程骨架。
- 真实网关测试：请求抵达网关，返回 `FAIL_SYS_TOKEN_EMPTY` / `RGV587_ERROR`（当时缺握手）。
- 本地 mock 网关：成功解析分支验证通过。
