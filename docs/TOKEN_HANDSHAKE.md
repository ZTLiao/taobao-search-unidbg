# 有效签名 token 的获取与链路打通

> 目标：回答「怎么拿到有效签名 token、把链路真正打通」。
> 结论先行：**H5 网关的 token 由协议握手自动获取，本工程已实现并实测通过；app 私有 native 签名（x-sign）无法凭空离线生成，只能通过你自持的真机/签名服务接入；业务接口的风控拦截不属于签名层。**

---

## 1. 先分清两套签名体系

淘宝有两类 MTOP 网关，签名机制完全不同，**混用是常见错误**（上一版本工程就踩了这个坑：用 H5 网关却声称走 app native 签名）。

| | H5 网关 | App 网关 |
|---|---|---|
| 地址 | `h5api.m.taobao.com/h5/` | `acs.m.taobao.com/gw/` |
| 签名字段 | query `sign` | header `x-sign` / `x-sgext` / `x-mini-wua` / `x-umt` |
| 算法 | `MD5(token & t & appKey & data)`（公开标准） | SecurityGuard / libsgmain 白盒签名（私有） |
| token | 网关通过 `Set-Cookie: _m_h5_tk` 动态下发 | 设备指纹 + 会话，绑定真机环境 |
| 离线可否复现 | ✅ 可以，标准协议 | ❌ 基本不行，需真机运行时环境 |

本工程默认请求 H5 网关，因此**打通的正确路径是实现 H5 token 握手**，而不是去补 libsgmain。

---

## 2. token 到底从哪来

**`_m_h5_tk` 不是 APK 里的静态常量**，无法从 smali / SO 里抠出来。它是网关按会话动态签发的：

```
Set-Cookie: _m_h5_tk=<token>_<毫秒时间戳>; Path=/
Set-Cookie: _m_h5_tk_enc=<密文>; Path=/
Set-Cookie: cookie2=<...>; t=<...>; _tb_token_=<...>
```

- `token` = `_m_h5_tk` 值里**最后一个下划线之前**的部分；
- 首次请求没有 Cookie，网关返回 `FAIL_SYS_TOKEN_EMPTY` / `FAIL_SYS_TOKEN_EXPIRED` 并下发 token；
- 客户端解析出 token 后，按标准公式重算 sign，带 Cookie 重发即通过。

> 这正是此前真实网关测试里 `FAIL_SYS_TOKEN_EMPTY` 的根因：**不是签名算法错，是缺握手**。
> 所以「想办法获取有效 token」的正确答案是：**让客户端按协议完成握手**，而不是抓取或伪造一个固定值。

---

## 3. 握手时序（本工程实现）

```
MtopHttpClient.call()  (maxAttempts = max-retries + 1)
  │
  ├─ attempt#1  token=null
  │    sign = MD5("" & t & appKey & data)
  │    POST /h5/<api>/<v>/?...   （无 Cookie）
  │    ← FAIL_SYS_TOKEN_EXPIRED + Set-Cookie: _m_h5_tk=abc_1700000000000
  │    MtopTokenManager.absorb()  → token="abc", source=handshake
  │
  ├─ attempt#2  token="abc"
  │    sign = MD5("abc" & t & appKey & data)
  │    POST 同上 + Cookie: _m_h5_tk=abc_...; _m_h5_tk_enc=...; cookie2=...
  │    ← SUCCESS::调用成功 + data.resultList
  │
  └─ ApiResponse(success=true, gatewayRet=SUCCESS, tokenState=handshake, attempts=2)
```

关键实现点：

| 组件 | 职责 |
|---|---|
| `sign/MtopTokenManager` | Cookie jar 会话（单例，跨请求复用）、解析 `_m_h5_tk`、token 类错误判定、BYO 注入、过期作废 |
| `sign/H5MtopSigner` | `MD5(token&t&appKey&data)` |
| `service/MtopHttpClient` | 握手重试闭环、自动吸收 `Set-Cookie`、`x-*` 签名头透传、Cookie 携带、响应分类 |
| `service/HumanBehaviorSimulator` | **会话级稳定 utdid**（握手期间设备指纹不能漂移，否则破坏会话一致性） |
| `controller/TokenController` | `/api/token` 查看/注入凭据、`/api/token/handshake` 主动握手 |

token 是会话级共享的：握手成功后，后续请求直接复用（`attempts=1`），与真机行为一致。

---

## 4. 四种签名后端（可插拔）

`sign/SignerRouter` 统一路由，`search.sign-backend` 全局配置，请求体 `signBackend` 单次覆盖。

| 后端 | 签名来源 | 需要 token | 适用场景 |
|---|---|---|---|
| `h5` **(默认)** | 标准 H5 握手自动获取 | ✅ 自动 | 协议层打通、H5 网关请求 |
| `rpc` | 你自建的 unidbg-server / 真机 frida-rpc | 可选透传 | 接入 app 私有 `x-sign` |
| `unidbg` | 本地补环境模拟 libsgmain | ❌ | 逆向研究（需按 HOOK_GUIDE 补 JNI） |
| `mock` | 离线确定性占位 | ❌ | 联调 / 降级 |

`rpc` 后端是接入有效 native 签名的合规途径：把 `(api, version, appKey, t, data, token, cookie)` POST 到 `sign.rpc.url`，签名由**你自己持有、自己授权的设备/环境**产生，本工程只做编排。典型部署就是另一个进程里的 unidbg-server（与本项目同源的 SpringBoot 骨架）。期望响应：

```json
{"sign":"...", "x-sign":"...", "x-sgext":"...", "x-mini-wua":"...", "t":"..."}
```

也可直接注入自持凭据，跳过自动握手：

```bash
# 方式 A：配置
mtop.token=<你的 _m_h5_tk token>
mtop.cookie=<完整 Cookie 串>

# 方式 B：请求体 / query
{"q":"连衣裙", "token":"...", "cookie":"_m_h5_tk=...; ..."}

# 方式 C：管理端点
curl -X POST /api/token -H 'Content-Type: application/json' \
  -d '{"token":"...", "cookie":"..."}'
curl -X POST /api/token -d '{"refresh":true}'   # 作废 token 并轮换设备身份
```

---

## 5. 实测结果（2026-11-22）

### 5.1 本地 mock 网关（完整闭环，`tools/e2e_test.sh` 一键复现）

```
[req1] mtop.taobao.wsearch.suggest  no-valid-token -> challenge (Set-Cookie _m_h5_tk)
[req2] mtop.taobao.wsearch.suggest  SIGN OK -> SUCCESS
[req3] mtop.taobao.wsearch.appsearch SIGN OK -> SUCCESS
[req4] mtop.taobao.wsearch.suggest  SIGN OK -> SUCCESS (suggestList=3)
[req5] ...PailitaoRecommend.recommend SIGN OK -> SUCCESS
[req6] mtop.taobao.wsearch.appsearch SIGN OK -> SUCCESS   (rpc 后端，经外部签名服务)
[sign-rpc] api=mtop.taobao.wsearch.appsearch token=present -> sign=c222b381..
PASS text_search / suggest / image_search / rpc_search    E2E_RESULT=PASS
```

`rpc_search` 的 `signBackend=rpc`、`signMeta._rpc=http://127.0.0.1:8098/api/sign`，证明「请求编排 → 外部签名服务 → 网关」这条可插拔签名源通路同样贯通；把 `tools/mock_sign_rpc.py` 换成真实 unidbg-server / 真机 frida-rpc 即可接入有效 native 签名。

`/api/token/handshake` 轨迹：
```
attempt#1 ret=TOKEN_REQUIRED tokenUpdated=true  token=present
attempt#2 ret=SUCCESS        tokenUpdated=false token=present
```

### 5.2 真实网关 `h5api.m.taobao.com`（少量探测）

| 接口 | 结果 |
|---|---|
| `/api/token/handshake` | ✅ **握手成功**，自动获取有效 `_m_h5_tk`（`source=handshake`），第 2 次请求 `SUCCESS`；Cookie 含 `_tb_token_ / t / cookie2 / _m_h5_tk_enc / _m_h5_tk` |
| `/api/search` | ⚠️ `RGV587_ERROR::SM::哎哟喂,被挤爆啦,请稍后重试!` → `gatewayRet=RISK_CONTROL` |
| `/api/image_search` | ⚠️ 同上，`RISK_CONTROL` |

**协议层已打通**：token 自动获取、sign 计算、Cookie 会话、重试、响应解析全部在真实网关验证通过。业务接口剩下的是**风控层**拦截。

---

## 6. 能力边界（重要，避免误判）

1. **风控不是签名能解决的。** `RGV587_ERROR` 是网关的滑块/设备/账号校验，属反自动化对抗，与 `sign` 是否正确无关。本工程**不提供、也不打算提供**风控绕过能力。工程会把这类响应准确分类为 `RISK_CONTROL` 并给出提示，而不是伪装成签名失败。
2. **native `x-sign` 无法离线凭空生成。** libsgmain 的签名强依赖真机运行时（设备指纹、白盒密钥、sgmain 数据文件），unidbg 补环境只能用于研究，产出被生产认可的签名需要把签名能力放在你自己的真机上（即 `rpc` 后端）。
3. **H5 token 有时效、绑定会话。** 网关返回 `TOKEN_EXPIRED` 时会自动刷新重算；`mtop.token-ttl-seconds` 仅用于 health 状态展示，不是硬过期。
4. **两套网关不要混用。** 若切到 `acs.m.taobao.com/gw/`（app 侧），必须同时换成 `rpc`/`unidbg` 后端提供 `x-sign`，H5 的 `sign` 不被接受。

### 合规与推荐路径

- 生产用途优先使用**淘宝官方开放平台（TOP / 淘宝开放平台）API**，走正式授权与配额；
- 若确需客户端协议级研究，请在**你自己持有、自己授权**的设备与账号上进行，凭据通过 `mtop.token` / `mtop.cookie` / `sign.rpc.url` 注入；
- 遵守目标站点的服务条款与 robots 约定，控制请求频率（工程已内置 `human` 行为模拟与随机延迟），不做高频抓取、不绕过验证码与风控。

---

## 7. 排错表

| `gatewayRet` | 含义 | 处理 |
|---|---|---|
| `SUCCESS` | 全链路成功 | 读 `items` / `rawData` |
| `TOKEN_REQUIRED` | 握手未完成或 token 失效 | 看 `handshakeTrail`；确认网关是否下发 `Set-Cookie`；或注入自持 token/cookie；调大 `mtop.token-handshake.max-retries` |
| `SIGN_REJECTED` | sign 校验失败 | 核对 appKey / data 是否一致；app 侧改用 `rpc` 后端接 `x-sign` |
| `RISK_CONTROL` | 风控（RGV587 / 滑块 / 设备校验） | 非签名问题：需合法设备凭据与账号授权，或改用官方开放平台 API |
| `LOCAL_ERROR` | 网络/解析异常 | 检查 `mtop.gateway` 可达性、超时、返回体格式 |
| `FAIL` | 其它网关失败 | 看 `ret` 原文与 `rawData`，切换 `signBackend` 对比 |

诊断字段：`gatewayRet` / `tokenState` / `attempts` / `hint` / `handshakeTrail` / `signMeta`，以及 `GET /api/health`、`GET /api/token` 的会话概览。
