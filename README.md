# 战舰少女R 脱机脚本复活工程

> 目标：让「护萌宝」系列战舰少女R脱机客户端（`simonkimi/core-protector-moe`、`ProtectorMoe/pc-protector-moe`）
> 能够在**当前版本**战舰少女R 上重新运行。
>
> 现状：**旧协议已全部作废，新协议已完整还原并实测打通到游戏服**；
> 尚缺最后一环——游戏主协议（TCP 10010）的二进制编解码器。

游戏实测版本：**v5.6.0**（versionCode 51000，资源版本 `0.0.629.1`）

---

## 一、结论速览

| 项目 | 状态 |
|---|---|
| 护萌宝客户端源码 | ✅ 已归档并读通（两代协议、完整 API 面） |
| 旧协议（v3.8 / v4.5） | ❌ **已作废**：域名 NXDOMAIN、密钥从客户端移除、REST 接口全 404 |
| 现行 HTTP 引导协议 | ✅ **完整还原并实测验证** |
| 现行服务器列表 | ✅ 6 个国服 + 多云镜像，全部实测 |
| 脱机连接游戏服 | ✅ **已跑通**（本机直连，服务端下发会话密钥） |
| **游戏主协议加密** | ✅ **已破译 = 明文 XOR `0xAE`** |
| **报文结构** | ✅ **已还原**（u32 总长度前缀帧，三条真实流 100% 切分） |
| **应用层消息** | ✅ **已还原**（u16 消息ID + protobuf 风格字段） |
| `lxdata` 容器（Lua 字节码） | ❌ 未解（网络侧不需要；要读全部业务逻辑才需要） |

---

## 二、现行协议（实测）

### 2.1 域名

| 用途 | 域名 | 端口 |
|---|---|---|
| 补丁/公告/服务器列表 | `xrpc.moefantasy.com` | 80 |
| 账号通行证（HTTPS） | `andpassportapi.moefantasy.com` | 443 |
| 游戏服认证 | `xr-server-N.moefantasy.com` | **10005** |
| **游戏主协议** | `xr-server-N.moefantasy.com` | **10010** |

多云镜像前缀：`tcloud-` / `aliyun-` / `hwhk-`。

### 2.2 补丁检查 → 服务器列表

```http
POST / HTTP/1.1
Host: xrpc.moefantasy.com
Content-Type: application/x-www-form-urlencoded; charset=utf-8

app_version=v5.6.0&app_id=xr_cn_release&os_type=android
&patch_list={"data_hd":"0.0.178.1","main":"0.0.629.1"}&channel=taptap
```

响应为 **zlib 压缩的 JSON**，含 `notice.server_list`（服务器名 / id / ip / port / 镜像）。

### 2.3 游戏服认证

```http
POST /auth/ HTTP/1.1        ← 注意端口是 10005
Host: xr-server-4.moefantasy.com

{"token":"<通行证 token>","channel":"hm_sdk_android"}
```

响应为**明文 JSON**：`account_id`、`account_guid`、`server_list` 等。

### 2.4 进入游戏

与 `xr-server-N.moefantasy.com:10010` 建立 TCP 长连接：
客户端首包 12 字节 → 进入游戏请求 362 字节 → 服务端回 ~73 KB 初始数据。

**该请求已被成功重放**（`tools/replay.py`），服务端返回 346 字节且开头与实机抓包逐字节一致，
说明该环节**无客户端指纹校验**。

---

## 三、工具说明

`tools/` 下是从零写的分析工具链，纯 Python 标准库 / shell，不依赖第三方包。

### 3.1 安装包分析（不必下载 3.3 GB）

| 工具 | 说明 |
|---|---|
| `remotezip.py` | **通过 HTTP Range 直接读远程 ZIP/APK**。`list` / `find` / `pull` / `head` 四个子命令 |
| `analyze_entries.py` | APK 条目体积分布分析 |
| `meta_strings.py` | IL2CPP `global-metadata.dat` 字符串抽取（含表头解析） |
| `strings.py` | 带偏移的字符串抽取，支持 `grep` / `range` / `around` |
| `kwstat.py` | 二进制逐关键词命中统计（ASCII + UTF-16LE） |
| `lxdata_probe.py` | `lxdata` 自定义容器熵与结构分析 |
| `elf_syms.py` | 极简 ELF `.dynsym` 导出符号列举器（用于确认能否按名字 hook） |

```bash
# 例：列出远程 APK 全部条目
python tools/remotezip.py list <apk_url> entries.txt
# 例：只抽取 global-metadata.dat
python tools/remotezip.py pull <apk_url> assets/bin/Data/Managed/Metadata/global-metadata.dat out.dat
```

### 3.2 网络与流量

| 工具 | 说明 |
|---|---|
| `dns_recon.py` | 子域爆破 + 泛解析检测 |
| `probe_hosts.py` | 主机端口连通性 + HTTP(S) 探活 |
| `pcap_analyze.py` | pcap → DNS 查询 / TLS SNI / 明文 HTTP 提取 |
| `pcap_streams.py` | **TCP 流重组**（双向，按序拼包） |
| `extract_resp.py` | HTTP 正文提取 + 压缩 / XOR / ECB 自动判定 |
| `flow_analyze.py` | 指定端口流的熵 / 字节频率 / 重复周期 / 明文串分析 |
| `transform_bf.py` | 简单变换暴力排除（XOR / 位反转 / 半字节交换 / 移位 / 加减） |
| `replay.py` | **重放捕获请求到真实游戏服** |
| `probe_api.py` | 老式 REST API 路径探测（结论：新服全部 404） |
| `dump_bodies.py` | 批量解压并美化抓到的响应正文 |

### 3.3 Android 运行时取证

| 工具 | 说明 |
|---|---|
| `mem_find.py` | 在内存 dump 中定位关键词并输出上下文 |
| `scan_mem.sh` / `scan_mem2.sh` | 设备端脚本：按 `/proc/PID/maps` 扫描进程内存（需 root） |

```bash
# 设备端 (root)
adb push tools/scan_mem2.sh /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/scan_mem2.sh"
adb shell "/data/local/tmp/scan_mem2.sh $(adb shell pidof <包名>) moefantasy xr_cn_release"
```

---

## 四、游戏主协议：✅ 已破译

### 4.1 加密

**明文 XOR `0xAE`** —— 单字节、全局固定，`libtolua.so` 的 `lxnet` 层注册的加密函数即为此。

破译路径：从导出符号发现 `lua_lxnet_messagepack_pushdata/getdata`
→ 反汇编得到报文结构 → 对已知明文位置试单字节 XOR，一击命中。

### 4.2 报文结构 ✅ 已在 3 条真实流上 100% 验证

```
加密 : 密文 = 明文 XOR 0xAE                       (单字节, 全局固定)
帧   : <u32 LE 总长度 L, 含自身 4 字节> + (L-4) 字节内容
填充 : 帧之间可夹 0xAE 填充 (明文 0xAE / 密文全 00), 解码时跳过
```

| 流 | 大小 | 帧数 | 消费率 | 跳过填充 |
|---|---|---|---|---|
| 服务端→客户端 | 63,563 B | 42 | **100.0%** | 144 B |
| 服务端→客户端 | 72,953 B | 28 | **100.0%** | 78 B |
| 客户端→服务端 | 412 B | 25 | **100.0%** | 0 B |

这条规则一次性解释了所有此前的「怪现象」：

- 被误读成「12 字节握手」的 `06 00 00 00 01 00`，头 4 字节**就是长度 6**；
- 重复出现的 17 字节块 `11 00 00 00 45 0d ...`，头 4 字节**就是长度 17**；
- `04 00 00 00` 是**长度 4 的空帧**；
- 服务端流开头的 8 字节 `0xAE` 与帧间填充都是**明文 0xAE 填充**。

> **踩坑记录**：一度以为长度字段在「6 字节头之后」，于是怎么都对不齐第三条消息，
> 还写穷举脚本去搜布局。真相是**长度在最前面且包含自身**。
> 另外 `libtolua.so` 反汇编出的「`offset+6` 写长度、负载从 `offset+10` 开始」
> 描述的是**内层嵌套结构**而非最外层传输帧——这是主要误导来源。

实现见 `tools/wsgr_proto.py`（加解密 + 切帧 + 跳过填充，含自测）。

### 4.3 应用层 = u16 消息ID + protobuf 风格字段

```
帧内容 = <u16 LE 消息ID> + <字段序列>
字段   = <tag><值>，tag = (field << 3) | wiretype
         wiretype=2 -> 后跟 1 字节长度，再跟该长度的数据
```

实测消息 ID（客户端 → 服务端）：

| 帧长 | 内容（hex） | ID | 含义 |
|---|---|---|---|
| 6 | `01 00` | **1** | 保活心跳（无字段） |
| 180 | `8b 13 \| 1a 00 \| 62 0a "Android 35" …` | **5003** | 登录 |
| 10 | `5f 1b 02 00 00 00` | **7007** | 登录子消息 |
| 10 | `64 1b 03 00 00 00` | **7012** | 登录子消息 |
| 86 | `6a 1b 12 24 <36字节UUID>` | **7018** | field 2 = UUID |
| 10 | `b3 1b 05 00 00 00` | **7091** | **动作消息**（点击后才出现） |
| 13 | `e0 1b \| 08 91 4e \| 06 00 00 00` | **7136** | **领取远征奖励**（field1 = 远征ID 10001） |

登录消息（ID 5003）字段：

| tag | field | len | 值 |
|---|---|---|---|
| `1a` | 3 | `00` | 空字段 |
| `62` | 12 | `0a` | `Android 35` |
| `5a` | 11 | `20` | 设备指纹（32 hex） |
| `52` | 10 | `20` | 设备指纹（32 hex） |
| `4a` | 9 | `20` | 设备指纹（32 hex） |
| `22` | 4 | `20` | 会话 token |
| `12` | 2 | `0e` | `hm_sdk_android` |

> **注意客户端流量极小**：一次 90 秒完整会话客户端只发 422 字节，
> 18 帧是心跳，真正业务消息只有 4 帧。动作消息只有 10 字节，容易淹没在心跳里。
> 识别方法是「对比点击前/点击后两次抓包取差集」——`b3 1b 05 00 00 00` 就是这样定位的。

### 4.4 端到端验证

`tools/wsgr_client.py` 直连 `xr-server-2.moefantasy.com:10010`，
发送抓取到的握手+进入游戏请求，服务端**下发了新会话密钥** `<REDACTED_SESSION_KEY>`；
73 KB 初始数据解密后含好友/演习名单（`Richelieu`、`Miyuki`…）、
字段名（`def`/`atk`/`torpedo`/`air_`）、客户端配置（`{"audit":false,…}`）。

### 4.5 ⚠️ 动作无响应：两次错误归因

**第一次**：以为「服务端限流」，还写进了文档。
❌ 错。次日 `/auth/` 返回 `error_code=1001`（token 失效）——
而失效 token 的症状（连接正常、心跳照常、动作静默）与"限流"**完全相同**。

**第二次**：以为「无响应 = 失败」。做了 4 组 A/B（完整/残缺登录块 × 序号递增/重复），
全部 0 响应。❌ 又错。最后抓**真机同类动作**作对照：

```
真机 客户端 -> 服务端:  msgid=7091  seq=5  hex=b3 1b 05 00 00 00
真机 服务端 -> 客户端:  只有心跳 3397 与推送 5957 —— 无任何针对性响应
```

**真机做同样动作也没有响应**，但奖励确实到账。
⇒ **"没有响应"不等于"动作失败"。**

**顺带纠正两个真 bug：**

1. **登录帧烧死旧 token**：抓包里的 180 字节登录帧，field 4 嵌着抓包当时的 token。
   直接重放 → 连接成功但会话绑的是过期凭据（症状同"限流"）。
   现改为 `patch_login_token()` **注入当前 token**。
2. **消息序号硬编码**：每条消息尾部 4 字节是**全局递增序号**
   （登录 1，7007/7012/7018 → 2/3/4，7767/7020 → 5/6，动作接续）。
   必须由会话维护递增。

**判据表：**

| 判据 | 限流 | 凭据失效 | 动作正常但无回执 |
|---|---|---|---|
| `/auth/` 返回值 | 正常 | `error_code != 0` | 正常 |
| 换新 token 后 | 仍无响应 | 恢复正常 | — |
| 服务端是否 RST | 不一定 | 常见 | 否 |
| **真机同类动作是否有响应** | — | — | **也没有** ✓ |
### 4.6 仍未解决：`lxdata` 容器

`script.script` / `config.conf` / `xbask.core` **不用** XOR 0xAE
（magic `lxdata` 为明文，载荷单字节 XOR 全空间试探无效）。

网络侧已不需要它。若要**穷尽全部业务逻辑**（出征/战斗/后勤每条消息的字段含义），
两条路：

| 路线 | 做法 |
|---|---|
| A（推荐） | **录制–回放 + 黑盒试探**：直接连服务器发消息、看响应，逐条确定字段语义 |
| B | 继续逆向 `lxdata`（`packet_open` @ `libtolua.so`），拿 Lua 字节码再反编译 |

已确认可用的 hook 落点（`.dynsym` 导出，含偏移）：

```
0x001088cc  _ZN5lxnet8Socketer8SendDataEPKvm
0x001086cc  _ZN5lxnet8Socketer21GetSendBufferByteSizeEv
0x0010588c  socketer_send_msg
0x00105c14  socketer_get_data
0x000e01e0  packet_add_file
0x000e12e8  packet_remove_file
```

---

## 五、旧协议（已作废，仅供对照）

| 旧东西 | 现状 |
|---|---|
| `login.jr.moefantasy.com` / `version.jr.moefantasy.com` | NXDOMAIN |
| `s1..s14.jr.moefantasy.com` (116.63.102.78) | 记录在，IP 不通 |
| `AuthHead: HMS 881d3SlFucX5R5hE` / `AuthKey: kHPmWZ4zQBYP24ubmJ5wA4oz0d8EgIFe` | 已从客户端移除 |
| URL 签名密钥 `<REDACTED_HEX32>` | 已从客户端移除，请求不再带 `t`/`e` |
| REST API（`api/initGame`、`pve/getPveData`、`boat/*` …） | 新服全部 **404** |
| `channel=100016` / `market=2` | 现为 `channel=taptap` / `app_id=xr_cn_release` |

旧客户端结构（供重写骨架参考）：
- `core-protector-moe`（Go，~10 KB，仅到"第一次登录拿 token"，**从未写完**）
- `pc-protector-moe`（Python，`Main.py` 253 KB，功能最全，基线 v4.5.0）
- `common-protector-moe`（TypeScript/Electron，API 面最清晰）
- `warshipgirl-rename`（Python，最小协议参考）

---

## 六、免责声明

- 本项目**仅供学习与技术研究**，严禁任何形式的商业化（代练、售卖、变相收费）。
- 请**仅使用测试账号**验证。脱机客户端流量特征与真实客户端差异较大，
  存在被风控识别并封号的风险，**请自行承担**。
- 不得用于破坏游戏公平性或侵害他人权益。
- 本仓库**不含任何账号凭据、token、内存转储或个人数据**；
  所有文档在发布前均经过自动脱敏（见 `tools/make_publish.py` 的脱敏清单）。

## 七、隐私 / 安全

仓库内容经过脱敏处理，以下内容**被明确排除**：

- `shared_prefs/hm_preference.xml`（含明文密码与 token）
- 抓包文件与 HTTP 正文（含会话 token、UID）
- 进程内存转储（`mem*.bin`）
- APK 抽取出的二进制（体积大且非必要）

贡献者请注意：**不要**把自己账号的 token、密码、UID、内存 dump 提交上来。
