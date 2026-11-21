# 淘宝首页搜索 / 图片搜索（拍立淘）完整链路分析

> 分析对象：`taobao-rebuild` 项目从 `com.taobao.taobao.apk` 逆向出的 smali 源码（13 个 dex，约 9.4 万 smali 文件）。
> 标注约定：✅ = smali 原文确认；⚠️ = 推断/需真机验证。

---

## 0. 一句话结论

两条搜索链路的**入口和参数完全不同，但最终汇聚到同一套 MTOP 网关 + SecurityGuard(libsgmain) 签名**：

- 文本搜索：`mtop.taobao.wsearch.appsearch` (v1.0)
- 图片搜索：`mtop.relationrecommend.PailitaoRecommend.recommend` (v1.0)
- 签名：两者都经 `mtopsdk.security.InnerSignImpl` → `ISecureSignatureComponent.signRequest()` (native, libsgmain) → 请求头 `mtop_sign` / `x-sign`

---

## 1. 文本搜索链路

```
[首页搜索框]
  com.taobao.search.searchdoor.sf.widgets.searchbar.SearchBarWidget (classes10)
    onClick / onEditorAction / onSearchBtnClicked(ZJLjava/lang/String;)
    getSearchEditContent() -> 关键词
        │  postEvent(tb/j0p)
        ▼
[搜索门 Widget] tb/o2p = SearchDoorWidget (classes10)
    onEventMainThread(tb/j0p) -> i(String,SearchBarHintBean,Z,J) -> 路由跳转
        ▼
[结果页] com.taobao.search.uniform.SearchActivity / SearchResultFragment (classes10)
    SearchActivity$a 从 Intent Uri 取 "q"
        ▼
[业务数据源] CommonBaseDatasource <- tb/gu6 装配
    tb/h1i extends tb/b54 : B(Map)->tb/r5j$a(apiName,"1.0","wsearch")
        ▼
[MTOP 请求] tb/h5p -> tb/g4p -> mtopsdk (classes12)
    InnerProtocolParamBuilderImpl 注入 sign/x-sign/mtop_sign
        ▼
[签名] tb/n9f = InnerSignImpl
    SecurityGuardManager.getSecureSignatureComp().signRequest(...)  <- native libsgmain
        ▼
[网络/结果] mtopsdk -> anet/channel -> CommonSearchResult -> SearchResultFragment
```

### 1.1 关键类（均为 ✅ 确认）

| 环节 | 类全名 | dex | 关键方法 |
|---|---|---|---|
| 搜索框 | `com.taobao.search.searchdoor.sf.widgets.searchbar.SearchBarWidget` | classes10 | `onClick`, `onEditorAction`, `onSearchBtnClicked`, `getSearchEditContent` |
| 多功能搜索框 | `...searchbar.MultiFunctionalSearchBarWidget` | classes10 | `performSearch` |
| 搜索门 | `tb/o2p`（原始 `SearchDoorWidget`） | classes10 | `onEventMainThread(tb/j0p)`, `i(...)` |
| 结果页 | `com.taobao.search.uniform.SearchActivity` | classes10 | Intent Uri 取 `q`（`SearchActivity$a` L222） |
| 数据源 | `com.taobao.search.sf.datasource.CommonBaseDatasource` | classes10 | `Q(tb/c11)`, `setParams(Map)` |
| API 配置 | `tb/c11` / `tb/b54` | classes10 | `a()` 工厂：`const-string "mtop.taobao.wsearch.appsearch"` / `"1.0"` / `"wsearch"` |
| 请求构造 | `tb/h1i` | classes10 | `B(Map)`, `q(Map,tb/gy$c)` |

### 1.2 MTOP API（✅ 原文照抄）

| API | 版本 | 位置 | 用途 |
|---|---|---|---|
| `mtop.taobao.wsearch.appsearch` | 1.0 | `classes10/tb/c11.smali:120`, `tb/b54.smali:294` | 主搜索 |
| `mtop.taobao.wsearch.suggest` | 1.0 | `classes9/tb/eb7.smali`, `tb/mt3.smali` | 联想词 |
| `mtop.relationrecommend.MtopRecommend.recommend` | 1.0 | `classes8/tb/f1p.smali:9` | TPP 个性化分支 |

### 1.3 请求参数（✅）

- 关键词 `q`：`SearchDoorContext.smali:322` 写入 ConcurrentHashMap；`CommonSearchContext` 白名单含 `q`/`from`/`search_action`/`jarvisDisable`/`changedAddress`。
- sug 参数（tb/eb7）：`area=active_page`, `src=c2c`, `history=off`, `action=del/clean`, `q`。
- 设备参数（tb/owq `SuggestApiBaseRequest.e()`）：`utd_id`, `ttid`, `code`, `elderHome`。
- ⚠️ `page`/`pageSize` 字面量未在主搜索请求类中直接出现（由服务端驱动的参数 Map 携带）；本工程按通用惯例补上。

---

## 2. 图片搜索（拍立淘）链路

```
[首页搜索框相机图标 / "拍立淘"]
  com.etao.feimagesearch.TaoInit (classes4)
    "拍立淘" -> h5.m.taobao.com/tusou/index.html -> initCapture(url)
        ▼
[拍照页] com.etao.feimagesearch.capture.CaptureActivity (extends FEISBaseActivity)
    相机: Camera1Holder implements Camera.PreviewCallback（直接取预览帧）
    相册: CaptureAlbumWidget + ContentResolver.query（应用内相册）
        ▼
[图片处理] com.etao.feimagesearch.util.BitmapUtil
    encodeBitmap(bmp, JPEG, 70) -> base64
    compressToBase64WithSizeLimit: 超限每次 -5 quality，最小 50
        ▼
[上传+识别] tb/ovn.c(Bitmap,Map,listener) -> tb/pft.c()
    strimg = base64(JPEG,70), region, full_region_size
    -> ImageSearchMtopUtil.j(appId,apiName,apiVersion,params,listener)
    -> tb/u7j.a -> MtopBusiness
        ▼
[签名+网络] InnerProtocolParamBuilderImpl -> SecurityGuard signRequest -> 网关
        ▼
[结果页] com.etao.feimagesearch.IrpActivity / IrpV2Presenter / IrpWidget
    data.result[0].url -> 商品列表
```

### 2.1 关键结论（✅ 全部确认）

1. **主模块**：`com.etao.feimagesearch`（classes4，400+ smali）。
2. **主 API**：`mtop.relationrecommend.PailitaoRecommend.recommend` v1.0。API 名从 Rainbow 配置 `tppApiBackup`/`tppApiVerBackup` 读取，默认回退即此值（`tb/lg4.F1()` L2057 / `G1()` L2341）。
3. **图片传输方式**：不是 multipart、不是独立 CDN 上传。**JPEG(q=70)→base64 放进参数 `strimg`，随 MTOP 请求体 POST**。上传+识别是同一个接口。⚠️ 未找到 `upload.taobao.com` 之类独立上传域名。
4. **入口**：`TaoInit.smali:1899` 的 `"拍立淘"` → H5 `https://h5.m.taobao.com/tusou/index.html?...&pssource=sy`。⚠️ 具体哪个 View 的 onClick 调起 TaoInit 未直接定位（经 H5/路由中转）。
5. **结果解析**：`data.result[0]` 里的 `url` 字段（ImageSearchMtopUtil.q()）。
6. **拍立淘自有 JNI**：`PailitaoCUtil` 的 native 方法（`detectWatermark`/`scaleYuv`/`yuv420pToBitmap`）是**水印检测+YUV 转换**，不是签名。

### 2.2 请求参数（✅ ImageSearchMtopUtil.h / tb.pft）

| 参数 | 值 | 来源 |
|---|---|---|
| `strimg` | base64(JPEG,70) | `tb/pft.c()` L521-625 |
| `searchimg` | 已上传图片 URL（URL 路径用） | `tb/pft` |
| `region` / `full_region_size` | `0,w,0,h` 或 `l,r,t,b` | `tb/pft.c()` |
| `m` / `n` | `api4etao` / `60` | `ImageSearchMtopUtil.h` L1259 / L1166 |
| `biz_type` / `subSearchType` | `pai` / `imageText_v3` | 同上 |
| `appId` | `32969` | `IrpV2Presenter.smali` |
| `_sid_` / `scene` | `69148` / `multiObject` | `IrpV2Presenter.smali:14724` |
| `extraParams` | `use_multi_cat:1;use_pid_summary:1;...` | `ImageSearchMtopUtil.g()` |
| `utd_id`, `sversion`, `deviceLevel`, `LBS`... | 设备指纹 | `ImageSearchMtopUtil.h()` |
| `appId` 外层封装 | `{"params":"{...}","appId":"32969"}` | `ImageSearchMtopUtil.j()` |

---

## 3. 签名链路（两条链路共用）✅

```
InnerProtocolParamBuilderImpl.buildParams (classes12)
  -> MtopConfig.sign : tb/kqd (ISign)
  -> tb/n9f = mtopsdk.security.InnerSignImpl
     -> SecurityGuardManager.getSecureSignatureComp()
        -> ISecureSignatureComponent.signRequest(SecurityGuardParamContext, authCode)
           paramMap["INPUT"] = "api&version&appKey&t&data"
           -> native: libsgmain / libsgmiddletier / libsgsecuritybody
```

- 注入点：`classes12/mtopsdk/mtop/protocol/builder/impl/InnerProtocolParamBuilderImpl.smali:1343`（`MtopConfig.sign`）、`:2123`（`"mtop_sign"`）、`:2134`（`"x-sign"`）。
- 实现：`classes12/tb/n9f.smali`，字符串 `" in mtopsdk/security/InnerSignImpl"`（L263）；L3039 `getSecureSignatureComp()`，L3055 `signRequest()`，错误日志 `"[getCommonHmacSha1Sign] ISecureSignatureComponent signRequest error"`。
- SO：`classes/com/alibaba/wireless/security/framework/e.smali:8531-8535` 加载 `libsgmain` / `libsgmiddletier` / `libsgsecuritybody`。
- APK 内 SO：`lib/arm64-v8a/libsgmain.so`(112K)、`libsgmainso-6.8.261102.so`(2.9M)。

> 签名输入串 `INPUT` 的格式（`api&version&appKey&t&data`）来自 smali 中 `tb/n9f` 对各字段 put 到 paramMap 的观察，是 MTOP 通用做法；真实分隔符与顺序需按目标版本 verbose 日志最终确认。

---

## 4. 本工程与链路的对应关系

| 链路环节 | 本工程实现 |
|---|---|
| 搜索框/拍照 UI | 不在服务端复现（HTTP API 直接收关键词/图片） |
| 文本搜索数据源 | `service/TextSearchService` |
| 图片 base64 压缩 | `service/ImageSearchService`（`strimg`/`region`/拍立淘参数） |
| 人类行为模拟 | `service/HumanBehaviorSimulator`（UA/utdid/ttid/headers/延迟） |
| MTOP 请求构造 | `service/MtopHttpClient`（对应 InnerProtocolParamBuilderImpl） |
| SecurityGuard 签名 | `sign/UnidbgMtopSigner`（unidbg 模拟 libsgmain）+ `sign/MockMtopSigner`（离线） |
| 结果解析 | `MtopHttpClient.parse` / `extractItems`（`data.resultList` 等） |
| 对外接口 | `controller/SearchController` |
| H5 token 握手 | `sign/MtopTokenManager` + `sign/H5MtopSigner` + `MtopHttpClient` 重试闭环 |
| 签名源接入 | `sign/SignerRouter`（h5/rpc/unidbg/mock）+ `sign/RpcMtopSigner` |
| token 会话管理 | `controller/TokenController`（`/api/token`、`/api/token/handshake`） |

---

## 5. 签名与 token 握手（协议层，2026-11-22 补充）

第 3 节描述的是 **app 私有 native 签名**（`libsgmain` → `x-sign` / `mtop_sign`）。而本工程实际请求的 `h5api.m.taobao.com/h5/` 是 **H5 网关**，用的是另一套公开标准签名，二者不可混用：

```
app 侧:  acs.m.taobao.com/gw/  + x-sign/x-sgext/x-mini-wua (libsgmain native)
H5 侧:  h5api.m.taobao.com/h5/ + sign = MD5(token & t & appKey & data)
```

H5 的 `token` **不是 APK 里的静态常量**，而是网关在首次请求时通过 `Set-Cookie` 动态下发：

```
请求 1（无 Cookie）  -> FAIL_SYS_TOKEN_EMPTY / FAIL_SYS_TOKEN_EXPIRED
                        Set-Cookie: _m_h5_tk=<token>_<毫秒ts>; _m_h5_tk_enc=...; cookie2=...; t=...
请求 2（带 Cookie）  -> sign = MD5(token & t & appKey & data) -> SUCCESS
```

这解释了此前真实网关测试里 `FAIL_SYS_TOKEN_EMPTY` 的根因：不是签名算法错，而是**缺握手**。本工程据此实现：

- `MtopTokenManager`：Cookie jar 会话、解析 `_m_h5_tk`、token 类错误判定、BYO 凭据注入、过期作废；
- `H5MtopSigner`：`MD5(token&t&appKey&data)`；
- `MtopHttpClient`：握手重试闭环（最多 `mtop.token-handshake.max-retries+1` 次），响应 `Set-Cookie` 自动吸收，token 变化后重算 sign 重发；
- `HumanBehaviorSimulator`：会话级稳定 utdid（避免握手期间设备指纹漂移）。

**实测（2026-11-22，真实网关）**：`/api/token/handshake` 自动获取到有效 `_m_h5_tk`（`source=handshake`，cookieKeys = `_tb_token_ / t / cookie2 / _m_h5_tk_enc / _m_h5_tk`），第 2 次请求返回 `SUCCESS`——协议层握手确实打通。但 `search` / `image_search` 业务接口返回 `RGV587_ERROR`（`gatewayRet=RISK_CONTROL`），属网关风控层拦截，**不是签名层问题**，需真实设备凭据/账号授权或官方开放平台 API。详见 `docs/TOKEN_HANDSHAKE.md`。
