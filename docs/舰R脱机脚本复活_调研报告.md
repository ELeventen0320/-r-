# 战舰少女R「护萌宝」脱机脚本复活调研报告

> 调研日期：2026-10-06
> 目标：复活 `ProtectorMoe` / `simonkimi` 的「护萌宝」系列脱机（headless）客户端，使其能在**当前版本**战舰少女R上正常挂机
> 结论：**目标可行，但不是一个"改几个常量"的活儿；当前版本的服务端入口需要重新获取，且客户端已加上 Lua 层加密。**

工作目录：`C:\Users\26912\Projects\wsgr-rt`

---

## 一、结论速览

| 项目 | 状态 | 依据 |
|---|---|---|
| 护萌宝脱机客户端源码 | ✅ 已全部拿到并读通 | GitHub 存档，2020–2023 |
| 完整 API 面 + 两代签名方案 + 密钥 | ✅ 已还原 | 源码硬编码 |
| 老登录/版本域名 | ❌ **已死（NXDOMAIN）** | DNS 实测 |
| 老游戏服 `s1..s14` | ⚠️ DNS 记录还在，但 IP 不通 | TCP 实测 |
| 当前游戏版本 | ✅ v5.6.0（2026-06-16 构建） | 官网 CDN |
| 当前客户端架构 | ✅ Unity + **tolua#（Lua）** + IL2CPP | APK 实测 |
| 当前 API 端点 / 签名密钥 | ❌ **不在 C# 层，拿不到** | 元数据/so 全文检索为空 |
| 业务逻辑 | ❌ **被 `lxdata` 加密容器包住** | 熵 7.95/8 |
| 网络层 | ⚠️ `lxnet` 自带加解密 + 打包 ENet(UDP) | `libtolua.so` 符号 |

**一句话**：引擎（骨架）还在而且完整，但"路"和"钥匙"都换了——域名没了、C# 层不再硬编码端点、Lua 业务逻辑被加密。

---

## 二、护萌宝是什么（已完全掌握）

四个仓库构成一套完整系统：

| 仓库 | 语言 | 最后提交 | 角色 |
|---|---|---|---|
| [`simonkimi/core-protector-moe`](https://github.com/simonkimi/core-protector-moe) | Go | 2020-05 | **Headless 客户端核心**（协议层） |
| [`ProtectorMoe/pc-protector-moe`](https://github.com/ProtectorMoe/pc-protector-moe) | Python | 2023-07 | 电脑版 GUI（功能最全） |
| [`ProtectorMoe/common-protector-moe`](https://github.com/ProtectorMoe/common-protector-moe) | TypeScript/Electron | 2023-01 | 跨平台版（API 面最清晰） |
| [`ProtectorMoe/pe-protector-moe`](https://github.com/ProtectorMoe/pe-protector-moe) | Java | 2020-07 | 手机版 |
| [`simonkimi/warshipgirl-rename`](https://github.com/simonkimi/warshipgirl-rename) | Python | 2019-11 | 最小协议参考实现 |

`core-protector-moe` 的全部代码只有 11 个文件、约 10 KB，README 停在"已经完成第一次登录获取token"——**这个项目从来没写完过**。真正的功能在 pc / common 版里。

### 2.1 第一代协议（3.8.x，`warshipgirl-rename`）

```
1) GET  http://version.jr.moefantasy.com/index/checkVer/3.8.1/100016/2&version=3.8.1&channel=100016&market=2
        → { version.newVersionId, loginServer, ... }
2) POST {loginServer}index/passportLogin/{url_end}
        body: username=<base64>&pwd=<base64>       → Set-Cookie
3) GET  {server}api/initGame?&crazy=0{url_end}     → zlib 压缩的 JSON
4) GET  {server}boat/renameShip/{id}/{urlencode(name)}/{url_end}
```

**URL 尾部签名（请求防篡改）**：
```
url_end = &t={毫秒时间戳}&e={md5(t + "<REDACTED_HEX32>")}
          &gz=1&market=2&channel={channel}&version={version}
```

> **密钥 `<REDACTED_HEX32>` 是硬编码在客户端的**，这是整条链上最有价值的一把钥匙。

### 2.2 第二代协议（4.1.0，`core` / `common`）

登录前端换成了 HMAC-SHA1 签名：

```go
AuthHead = "HMS 881d3SlFucX5R5hE"
AuthKey  = "kHPmWZ4zQBYP24ubmJ5wA4oz0d8EgIFe"
channel  = "100016" (Android) / "100015" (iOS)
```

```
Authorization: HMS 881d3SlFucX5R5hE:{base64(HMAC-SHA1(AuthKey, "POST\n" + Date + "\n" + path))}
Date: <RFC1123 GMT>
Content-Type: application/json
User-Agent: okhttp/3.12.1
```

### 2.3 完整 API 面（已还原，供复活时对照）

**登录链**
```
GET  {urlVersion}                                   → 版本 / loginServer / hmLoginServer
POST {hmLoginServer}1.0/get/login/@self             → access_token   (zlib)
POST {hmLoginServer}1.0/get/userInfo/@self          → 校验 token     (zlib)
GET  {loginHead}index/hmLogin/{token}               → userId / serverList
GET  {host}index/login/{userId}?client_version=..&udid=..&phone_type=..
GET  {host}api/initGame?&crazy=0                    → userShipVO...
GET  {host}pve/getPveData/
```

**战斗 / 玩法**（注意 `cha11enge` 是**数字 1 伪装字母 l** 的防爬写法）
```
{head}/cha11enge/{map}/{fleet}/0/     {head}/newNext/          {head}/spy/
{head}/dealto/{node}/{fleet}/{format}/  {head}/getWarResult/{0|1}/  {head}/SkipWar/
explore/start/{fleet}/{map}/          explore/getResult/{map}/
boat/supplyBoats/[{ids}]/0/0/         boat/repair/{ship}/0/     boat/repairComplete/{dock}/{ship}/
boat/instantRepairShips/[{ids}]/      boat/rubdown/{ship}       boat/lock/{ship}/
dock/dismantleBoat/[{ids}]/{0|1}/     pve/selectBuff/{buff}     pevent/setFleet/{fleet}/
pevent/getPveData/                    pvp/getChallengeList/     pvp/challenge/{uid}/{fleet}/{fmt}/
friend/getlist/                       friend/visitorFriend/{uid}/
campaign/getFleet/{map}/              campaign/challenge/{map}/{format}/
```

**通用约定**：所有响应 `gz=1` → **zlib 压缩的 JSON**；所有请求带 `t`/`e` 签名。

### 2.4 最新已知可用基线 = v4.5.0（2023-07）

`pc-protector-moe/Main.py`（253 KB 单文件，功能最全）用的是**比 core/common 版更新的 4.5.0**：

```python
url_version = 'http://version.jr.moefantasy.com/index/checkVer/4.5.0/100016/2&version=4.5.0&channel=100016&market=2'
self.res    = 'http://login.jr.moefantasy.com/index/getInitConfigs/'
self.channel = "100016"
```

且**支持五个区服**（复活时可作多区服模板）：

| 区服 | channel | 版本检查 | 登录入口 |
|---|---|---|---|
| 国服安卓 | 100016 | `version.jr.moefantasy.com` | `login.jr.moefantasy.com` |
| 国服 iOS | 100015 | 同上 | `loginios.jr.moefantasy.com` |
| 台服 | 100033 | 同上 | `login.jr.moepoint.tw` |
| 日服 | 100024 | 同上 | `loginand.jp.warshipgirls.com` |
| 英/欧服 | 100060 | 同上 | `enlogin.warshipgirls.com` |

> **时间线**：最新已知可用 **v4.5.0（2023-07）** → 当前 **v5.6.0（2026-06）**，中间隔了约 3 年。
> `pc-protector-moe/Main.py` 是重写 headless 客户端时**最有价值的骨架参考**（253 KB 完整业务逻辑）。

---

## 三、当前版本实测（这是坏消息的部分）

### 3.1 老域名已死

用阿里 DNS(223.5.5.5)、Google DNS(8.8.8.8) 双重复核：

```
login.jr.moefantasy.com         → NXDOMAIN    ❌ 死
version.jr.moefantasy.com       → NXDOMAIN    ❌ 死
jr.moefantasy.com               → NXDOMAIN    ❌ 死
login.jianniang.com             → NXDOMAIN    ❌ 死
s1..s14.jr.moefantasy.com       → 116.63.102.78 (同一 IP)   记录在，但 TCP 80/443 全部超时
```

> ⚠️ **注意本机网络存在污染迹象**，因此"不通"的结论要打折：
> - `passport.jianniang.com` → `192.168.1.74`（**私网地址**，公网 DNS 不可能返回）
> - `download.moefantasy.com` → `169.254.254.254`（**链路本地地址，典型黑洞**）
>
> 建议换一台干净网络（或关掉本机代理）复测 `s2.jr.moefantasy.com`。

### 3.2 当前版本 v5.6.0

官网 `moefantasy.com` 指向 `static.jianniang.com`，安卓包：
```
https://xrcdn3.moefantasy.com/unity/package/android/hm_android/v5.6.0cn_normal.apk
Content-Length: 3,338,247,606   Last-Modified: 2026-06-16
```

**CDN 支持 HTTP Range（206）**，所以不必下 3.3 GB——我用自写的 `remotezip.py`
按字节区间只抽取需要的文件（中央目录仅 1.45 MB，16,884 个条目）。

### 3.3 客户端架构：Unity + tolua# + IL2CPP

```
assets/data/**            2.44 GB   Unity 资源包 (.unity3d)
assets/data_extra/**      585 MB
assets/config.conf        111 MB    ← lxdata 容器
lib/arm64-v8a/libil2cpp.so 50 MB
lib/arm64-v8a/libtolua.so  4.9 MB   ← Lua 运行时 + LuaSocket
assets/script.script       13.6 MB  ← lxdata 容器（Lua 业务逻辑！）
assets/32bits.script.script 13.6 MB ← 32 位版
assets/data/*.mp4          59 MB
```

### 3.4 致命发现：端点不在 C# 层

对 `global-metadata.dat`（8.1 MB，**标准未加密** IL2CPP v31）、`libil2cpp.so`（50 MB）、
`classes.dex`（9.3 MB）做逐关键词全文检索：

| 关键词 | il2cpp.so | classes.dex | metadata | 说明 |
|---|---|---|---|---|
| `checkVer` | 0 | 0（仅同名 Java 方法） | 0 | ❌ |
| `hmLogin` | 0 | 0 | 0 | ❌ |
| `getInitConfigs` | 0 | 0 | 0 | ❌ |
| `jianniang` | 0 | 0 | 0 | ❌ |
| `ade2688f` | 0 | 0 | 0 | ❌ **老密钥已不在客户端** |
| `moefantasy.com` | 0 | **1** | 0 | ⚠️ 仅裸域名，无子域 |
| `HMS ` | 0 | 1 | 0 | ⚠️ 配合 `HMException.java`/`HMLog.java` 等 |

`classes.dex` 中那一处上下文（DEX 字符串池按字母序）：
```
...modulus..moefantasy.com..monitor..monitor.kt..monitorEnter...
...HM..HMException.java..HMLoadingDialog.java..HMLog.java..HMS ..HMSubscriber.java...
```
→ 幻萌的 `HM*` Java SDK 还在，但**域名是运行时拼接的**，客户端不存完整 URL。

### 3.5 业务逻辑被 `lxdata` 加密容器包住

`assets/script.script` 与 `assets/config.conf` **同一个容器格式**：

```
偏移 0:  6c 78 64 61 74 61 00 00     "lxdata\0\0"
偏移 8:  03 00                        version = 3
偏移 10: 3e e3 08 e3 07 b4 ff e0 ...  ← 从这里开始是不可读数据
```
- 熵 = **7.9513 / 8.0**（几乎完全随机 → 加密或压缩）
- 零字节比例 0.0043（纯随机理论值 1/256 = 0.0039）→ **强烈指向加密**
- 全文搜不到任何 `.lua` 文件名或 Lua 标识符 → 连文件表都是加密的

### 3.6 加载器已定位（复活的唯一突破口）

`libtolua.so` 里带调试信息，直接暴露了实现文件名与字段：

```
../../base/filepacket.c
  lxdata
  packet path:%s
  packet head size:%d
  in packet file num:%d
  max file size:%d
  packet data size:%d
  packet free block size:%d
  packet type:%d
  packet errorcode:%d
  file list info:
  file head_size:%d
  this block size:%d
  file size:%d
  file name:%s
  file in packet position:%d
  free block list:
  rebuild_temp_
导出符号: packet_open / packet_read_file / packet_add_file_by_data / packet_remove_file /
          packet_try_rebuild / crosspacket_script_dofile / crosspacket_reload_all_script_packet
```

→ 这是一个**支持增删改、带空闲块链表的小型归档格式**（不是单纯压缩包）。
→ 说明格式本身可能未加密，但**所包含的文件内容是加密/压缩的**。

同时发现**网络层自带加解密**：
```
lxnet::Socketer::SetEncryptKey / SetDecryptKey / UseEncrypt / UseDecrypt
socketer_set_encrypt_function / socketer_set_decrypt_function
AES_SetDecryptKey / AES_CBC_Decrypt / AES_GCM_Decrypt / rijndaelDecrypt
md5_sum_data / MD5Init/MD5Update/MD5Final
luaopen_enet_packet / enet_packet_create        ← 打包了 ENet（UDP 传输）
```

---

## 四、工程量评估与三条路线

### 路线 A（**推荐先做**）：抓真实流量 —— 成本低、见效快

老客户端 3.8/4.1 用的是**明文 HTTP**。若当前版本登录/API 仍是 HTTP，
用 mitmproxy / Fiddler 抓一次就能直接拿到：**当前域名、参数、签名方式、密钥、版本号**。

- 已知的现成工具：[`lone-wolf-akela/WSG_FiddlerPlugin`](https://github.com/lone-wolf-akela/WSG_FiddlerPlugin)（Fiddler 插件，专为舰R 调试写的）
- 环境你也有了：MuMu 模拟器（VM 0，Android 15，当前未启动）
- 预估：**半天～2 天**拿到完整现行协议

风险：若登录也上了 TLS 且做了证书固定（pinning），或走 `lxnet` 加密通道，则需要 Frida 脱壳级别的介入。

### 路线 B（兜底）：逆向 APK

1. 逆向 `libtolua.so` 的 `packet_open` / `packet_read_file` → 解出 `lxdata` 容器
2. 抽出 Lua 脚本 → 反编译 LuaJIT 字节码
3. 找到 HTTP 封装与签名逻辑 → 拿到现行密钥
4. 破解 `lxnet` 的 `SetEncryptKey` 与 AES 参数
5. 在上述基础上重写 headless 客户端

预估：**2～6 周**。工具链目前这台机器还缺（无 git/go/node/jadx/IDA）。

### 路线 C：放弃脱机，转有头方案

[`OpenWSGR/AutoWSGR`](https://github.com/OpenWSGR/AutoWSGR)（2026-10 仍活跃）、
[`Saratoga-Official/MRA`](https://saratoga-official.github.io/MRA/)（2026-10 仍活跃）、
[`Alcatraz-Zhang/warship-girls-r-event-runner`](https://github.com/Alcatraz-Zhang/warship-girls-r-event-runner)（MuMu ADB，2026-08）
都基于 ADB + 截图 + OpenCV/OCR，维护活跃，**今天就能用**。
代价：需要开模拟器、占资源、速度慢，且本质上和脱机是两套技术。

---

## 五、风险提示

1. **账号风险**：舰R 官方对脚本有明确打击（社区讨论见知乎《战舰少女R的脚本问题严重到了什么程度？》）。脱机客户端因为**不走游戏客户端**，流量特征与真人差异极大，被风控识别和封号的风险高于 ADB 方案。建议**用小号先验证**。
2. **法律/协议**：仅限个人学习研究，不得商用、不得代练收费（AutoWSGR 等项目均有此声明）。
3. **时效性**：本报告的域名/版本信息是 2026-10-06 的快照，幻萌随时可能再换。

---

## 六、已产出的可复用资产

| 文件 | 用途 |
|---|---|
| `probe/remotezip.py` | **通过 HTTP Range 直接读远程 ZIP/APK**，不下整包。`list`/`find`/`pull`/`head` |
| `probe/dns_recon.py` | 子域爆破 + 泛解析检测 |
| `probe/probe_hosts.py` | 主机端口连通性 + HTTP(S) 探活 |
| `probe/meta_strings.py` | IL2CPP `global-metadata.dat` 字符串抽取（含表头解析） |
| `probe/kwstat.py` | 二进制逐关键词命中统计（ASCII + UTF-16LE） |
| `probe/strings.py` | 带偏移的字符串抽取，支持 `grep`/`range`/`around` |
| `probe/lxdata_probe.py` | `lxdata` 容器熵/结构分析 |
| `probe/analyze_entries.py` | APK 条目体积分布分析 |
| `notes/apk_entries.txt` | v5.6.0 APK 全部 16,884 条目索引 |
| `notes/metadata_strings.txt` | IL2CPP 元数据全部字符串 |
| `apk/*` | 已抽取的 `global-metadata.dat` / `libil2cpp.so` / `libtolua.so` / `classes.dex` / `script.script` |

---

## 七、下一步建议

1. **先做路线 A**：启动 MuMu、装 v5.6.0、挂代理抓一次登录流量。这一步的投入产出比远高于逆向 APK。
2. 抓包同时，用干净网络复测 `s2.jr.moefantasy.com` 是否真的死了。
3. 若抓包证明是明文 HTTP → 直接进入"按现行协议重写 headless 客户端"，用已还原的 API 面做对照。
4. 若抓包受阻 → 再投入路线 B，从 `packet_open` 开始啃 `lxdata`。
