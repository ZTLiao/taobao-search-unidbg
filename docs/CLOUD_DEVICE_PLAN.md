# ARM 云真机接入方案（免登录文本/图片搜索的最终执行环境）

> 结论先行：本地 x86 主机三条路线全部堵死（见文末），目标可达（App UI 搜索已实证出真实数据），
> 但"有效签名 + frida attach"的执行环境必须来自真正的 ARM 设备。本方案用 ARM 云真机解决。

---

## 1. 为什么必须用 ARM 云真机

| 本地路线 | 失败原因（本轮实测/历史结论） |
|---|---|
| arm64 全系统模拟器 | emulator 36.1.9 不支持 x86 主机跑 arm64 系统，`PANIC: QEMU2 does not support arm64`；本机 SDK 只有 36/37，无法降级 |
| x86_64 模拟器 + berberis ARM 翻译 | 可 root、可装官方 APK，但淘宝 arm64 加固 so（`libpie_dynamic.so`）触发 host signal 11 → `Cannot process signal 11`，berberis 翻译层固有缺陷 |
| 非 root 真机 FP4 | frida-server ptrace 被 SELinux 拒；debuggable 无效；gadget 须重打包→SecurityGuard 签名失配（SecException 1927） |

云真机选型必须同时满足三点：
1. **真 ARM 架构**（不是 x86+翻译）—— 淘宝 arm64 so 原生运行；
2. **ROOT 权限** —— frida-server 能以 root 运行、attach 任意进程；
3. **远程 ADB 直连** —— `adb connect host:port`，frida/脚本才能操作设备。

---

## 2. 平台选择（2026-11 查证）

| 平台 | ROOT 能力 | ADB 直连 | 说明 | 推荐度 |
|---|---|---|---|---|
| **腾讯 WeTest** | ✅ 明确提供"支持 ROOT 的定制机"、ARM 服务器模拟器支持 root+xposed | ✅ 支持 ADB 模式 | `wetest.qq.com/products/cloud-phone`；定制机/模拟器支持 root，最契合 | ⭐⭐⭐ 首选 |
| **Testin 云测** | ⚠️ 需向客服确认 root 机型 | ✅ `adb connect debug1.testin.cn:10200` | 官方文档：`docs.testin.cn/远程真机/...使用adb进行调试.html` | ⭐⭐ |
| 阿里 MQC | ⚠️ 需确认 | ⚠️ 需确认 | 备选 | ⭐ |

> 关键动作：租机前**务必向平台确认该机型可 root**（WeTest 选"定制机"或"ARM 模拟器"类型）。
> 官方淘宝 APK 本身签名完整、不需要 root；但 frida-server attach 必须要 root。

---

## 3. 接入步骤（用户侧）

### 3.1 准备
1. 注册并充值 WeTest（或 Testin）账号，进入"远程真机/云手机"。
2. 选择 **Android -arm64-带 root** 的设备（WeTest:"定制机"或"ARM 模拟器"；Testin:咨询客服 root 机型）。
3. 租用后，在设备页面找到 **ADB 连接串**，形如 `host:port`（Testin 示例 `debug1.testin.cn:10200`）。

### 3.2 提供给我
把下面三项发给我，我即可接手自动化：
```
ADB 连接串:  <host:port>
是否 root:   <已确认 root / 待确认>
租用时窗:    <例如 2 小时，避免超时断连>
```

---

## 4. 拿到设备后我执行的自动化流程（已就绪）

整体复用现有 bridge + nativeSearch 链路，只是从 gadget 模式切回 frida-server attach 模式：

```bash
# 0) 连设备 + 确认 root
adb connect <host:port>
adb -s <host:port> root
adb -s <host:port> shell id            # 期望 uid=0

# 1) 装官方淘宝（签名完整，95MB，本工程 downloads 已有）
adb -s <host:port> install -r C:/Users/pc/Downloads/com.taobao.taobao_10.69.0.apk

# 2) push 并启动 frida-server（版本须与 PC 端 17.16.4 一致）
adb -s <host:port> push <frida-server-17.16.4-android-arm64> /data/local/tmp/fs
adb -s <host:port> shell 'chmod +x /data/local/tmp/fs; /data/local/tmp/fs -D &'

# 3) 预热淘宝（游客态，点过隐私弹窗，Mtop/SecurityGuard 初始化完成）
adb -s <host:port> shell 'monkey -p com.taobao.taobao -c android.intent.category.LAUNCHER 1'

# 4) 启动 bridge（完整签名 bundle，frida-server attach 模式）
python3 tools/frida_rpc_bridge.py --port 9091
#   - 不再设 FRIDA_GADGET_HOST → 走 frida.get_usb_device() + attach 淘宝主进程
#   - 用完整 rpc_sign_bundle.js（含 buildParams/n9f.r hook，抓真实四头 ground truth）

# 5) 低频跑原生搜索（文本 + 图片）
bash tools/native_search_safe.sh             # 文本 iphone17，最多 3 次间隔 20s
python3 tools/probe_image_native.py --image /tmp/tb_img/iphone18.jpg
```

### 4.1 frida-server attach 模式与 gadget 模式的关键差异

| 维度 | gadget（本机，失败） | frida-server attach（云真机，目标） |
|---|---|---|
| 签名 | 重打包破坏安全图片 → SecException 1927 | 官方 APK 签名完整 → 四头正常产出 |
| hook | implementation 替换触发 JNI SIGABRT | 外部 attach，hook 稳定（历史已验证） |
| 抓四头 | 不可能 | buildParams hook 可拿 x-sign/x-mini-wua ground truth |
| root | 不需要 | 需要（云真机提供） |

### 4.2 需要适配的代码（拿到设备后我做）
- `tools/frida_rpc_bridge.py`：`FRIDA_DEVICE=<host:port>` 传给 `frida.get_device()`；确认 attach 用主进程 PID。
- 确认 `rpc_sign_bundle.js`（完整版）在 attach 模式下能稳定抓到真实四头（历史第 11/18 章已验证可行）。
- 文本/图片搜索 data 用 `TextSearchService.nativeSearchData()` / `ImageSearchService` 的真机结构。
- 低频策略沿用 `native_search_safe.sh`（命中风控立即停）。

---

## 5. 风险与预期

1. **风控仍是服务端最后一道墙**：官方 APK + 真机 + 正常签名，游客态搜索的历史证据（`docs/real_iphone18_search.png`）显示能出真实数据；但高频会进冷却页，故坚持低频。
2. **root 检测 AuthSDK 600005**：历史 userdebug GSI 真机 root 触发登录组件 600005，但游客态搜索不需要登录；云真机 root 机型若也触发，需选"定制机 root 但不暴露 su 给 App"或用隐藏方案。
3. **平台合规**：云真机用于自动化测试；勿高频压测同一设备，避免被平台判定滥用。

---

## 6. 当前状态（2026-11-23）
- 本方案已制定，等待用户提供 ARM 云真机的 ADB 连接串。
- 本机 gadget 版淘宝仍装在 FP4 真机上（192.168.11.38:43481）；如不再需要可恢复官方版。
- bridge 已支持 `FRIDA_BUNDLE` 切换 bundle、`/api/search/native-main` 主线程路由；attach 模式无需 gadget 环境变量。
