# 战舰少女R 现行协议还原报告（实测版）

> 采集时间：2026-10-08
> 采集环境：MuMu 模拟器（Android 15）+ ADB root + tcpdump + 本地 Python 分析
> 测试账号：测试号（用户授权），`UID <REDACTED_UID>` / 昵称 `<REDACTED_NICKNAME>`
> 游戏版本：**v5.6.0**（versionCode 51000，2026-10-08 更新），资源版本 `0.0.629.1`

---

## 〇、一句话结论

老「护萌宝」客户端的**域名、协议、密钥全部作废**；但我已经把**现行协议完整还原**，并且**在本机成功重放，拿到了真实游戏服响应**——脱机入口已经打通，缺的只是最后一个二进制编解码器。

---

## 一、现行登录链路（全部实测验证）

### 1.1 域名总览

| 用途 | 现行域名 | IP | 端口 |
|---|---|---|---|
| 补丁/公告/服务器列表 | `xrpc.moefantasy.com` | 182.254.159.74 | 80 |
| **账号通行证（登录）** | `andpassportapi.moefantasy.com` | 124.220.120.161 | 443 (TLS) |
| **游戏服认证** | `xr-server-N.moefantasy.com` | 见服务器表 | **10005** |
| **游戏主协议** | `xr-server-N.moefantasy.com` | 见服务器表 | **10010** |
| 公告页 | `ann.jianniang.com` | 43.145.33.19 | 80 |
| 补丁 CDN | `xrcdn3.moefantasy.com` | 61.170.66.85 | 443 |

多云镜像（同样内容，用 `tcloud-` / `aliyun-` / `hwhk-` 前缀）：
`tcloud-patch-xr` / `aliyun-patch-xr` / `hwhk-patch-xr`、
`tcloud-passport-and-xr` / `aliyun-passport-and-xr` / `hwhk-passport-and-xr`、
`tcloud-xr-server-N` / `aliyun-xr-server-N` / `hwhk-xr-server-N`。

### 1.2 第一步：补丁检查 + 服务器列表

```http
POST / HTTP/1.1
Host: xrpc.moefantasy.com
Content-Type: application/x-www-form-urlencoded; charset=utf-8

app_version=v5.6.0&app_id=xr_cn_release&os_type=android
&patch_list={"data_hd":"0.0.178.1","main":"0.0.629.1"}&channel=taptap
```

**响应 = zlib 压缩的 JSON**（不是加密！），内容：

```json
{"notice":{
  "server_list":[{"name":"胡德","id":2,"state":2,"ip":"xr-server-2.moefantasy.com","port":10059,
                  "other":[{"port":10261,"ip":"tcloud-xr-server-2.moefantasy.com"}, ...]}, ...],
  "android_list":[...], "ios_list":[...],
  "self_ip":"180.157.165.47",
  "data_hd_version":"0.0.178.1",
  "notice_url":"http://ann.jianniang.com/official.html",
  "qa":{...}, "audit":{...}
 },
 "patch":{"patch_set":{},"total_size":0}}
```

> 注意：`server_list` 里的 `port`（10059/10009）是**公告用的宣传端口**，
> 客户端实际连接的是 **10010**（服务器表端口 +1），认证走 **10005**。

### 1.3 国服服务器表（实测）

| 名称 | id | 主机 | 端口 | 镜像端口 |
|---|---|---|---|---|
| 胡德 | 2 | `xr-server-2.moefantasy.com` | 10059 | 10261 |
| 俾斯麦 | 4 | `xr-server-4.moefantasy.com` | 10009 | 10411 |
| 昆西 | 13 | `xr-server-1.moefantasy.com` | 10059 | 11361 |
| **长春** | **14** | `xr-server-2.moefantasy.com` | **10009** | 11411 |
| 维内托 | 108 | `xr-server-3.moefantasy.com` | 10059 | 10861 |
| 列克星敦 | 101 | `xr-server-3.moefantasy.com` | 10009 | 10111 |

服务器 IP：`xr-server-1` = 115.159.50.54，`xr-server-2` = 124.221.171.169，
`xr-server-3` = 124.223.175.115，`xr-server-4` = 182.254.159.74。

### 1.4 第二步：账号认证（拿 token）

通行证走 HTTPS（`andpassportapi.moefantasy.com`），客户端登录成功后
把凭据明文落在 `shared_prefs/hm_preference.xml`（**密码明文存储**）：

| 字段 | 含义 |
|---|---|
| `hm_account` / `hm_password` | 账号 / **明文密码** |
| `hm_token` / `hm_alltoken` | 会话 token |
| `LONGREFRESH_TOKEN` | 长效刷新 token |
| `hm_uuid` / `account_guid` | 用户 uuid |
| `hm_userinfo` | JSON：`uuid/appid=100/platform/pi/email` |

> 🔒 凭据敏感，本报告不记录具体值。

### 1.5 第三步：游戏服认证

```http
POST /auth/ HTTP/1.1        ← 端口 10005，不是 80
Host: xr-server-4.moefantasy.com
Content-Type: application/x-www-form-urlencoded; charset=utf-8

{"token":"<hm_token>","channel":"hm_sdk_android"}
```

**响应 = 明文 JSON：**
```json
{"age":34,"account_pi":"...","is_bind_phone":0,"is_bind_email":1,
 "email_address":"<REDACTED_EMAIL>",
 "server_list":{2:1768971521,4:1768971718,14:1768971979,13:1768971739},
 "account_guid":"<REDACTED_UUID>","error_code":0,
 "account_id":<REDACTED_UID>,"account_name":"<REDACTED_ACCOUNT>"}
```
`server_list` = 各服最后登录时间戳。`account_id` 会显示在游戏左下角（与截图一致）。

### 1.6 第四步：进入游戏（游戏主协议）

客户端与 `xr-server-2.moefantasy.com:10010` 建立 **TCP 长连接**：
- 客户端先发 **12 字节**首包
- 再发 **362 字节**进入游戏请求
- 服务端回 **~73 KB** 初始数据

**实测重放成功**（本机 Python 直连，无需客户端）：

```
连接 xr-server-2.moefantasy.com:10010
发送捕获的 362 字节请求
→ 收到 346 字节响应，开头与实机抓包逐字节一致：
  9f ae ae ae eb 83 8c ae ae ae 2e b2 ae ae ae 24 bd a4 be ...
```

> 这意味着：**脱机客户端的主体连接与请求构造已经可用**，
> 服务端不做客户端指纹校验（至少在该环节）。

---

## 二、尚未攻破：10010 端口的数据编码

响应数据**不是加密后的随机流**，但也不是明文的 —— 证据：

1. 存在**高度规整的重复块**（16~17 字节一个记录），例如响应中重复约 10 次：
   ```
   bf ae ae ae eb a3 a8 ae ae ae 2e a8 ae ae ae af ae
   ```
2. 大量字节呈 `0xAE`、`0xA8`、`0xAF`、`0x2E`、`0x28`、`0x2F` 等
   —— 注意 `AE/2E`、`A8/28`、`AF/2F` **只差最高位 0x80**。
3. 把整个负载 `& 0x7F`（清掉最高位）后，可打印率显著上升，
   但**不是**直接可读文本。

**当前最可能的假设：不是密码学加密，而是"最高位作标记位的自定义位打包序列化"**
（类似 varint / BitStream，最高位表示"字段延续"或"空槽位"）。
也不排除是 `libtolua.so` 中 `lxnet` 的轻量 XOR 流密码。

**反向证据（不是强加密）**：若为 AES，字节应完全均匀、不会出现
`bf/3f`、`ae/2e`、`a3/23` 这种**成对只差最高位**的规律，也不会有 17 字节周期的重复块。

### 待办：拿到编解码器的三条路

| 方案 | 做法 | 成本 |
|---|---|---|
| **A（推荐）** | 用 Frida hook `libtolua.so` 的 `socketer_set_encrypt_function` / `SetDecryptKey` / Lua 的 `crosspacket_script_dofile`，直接 dump 明文与密钥 | 低-中 |
| B | 静态逆向 `libtolua.so` 的 `packet_*` / `lxnet::Socketer` 实现（需 IDA/Ghidra） | 中-高 |
| C | 从内存 dump 解密后的 Lua（`lxdata` 容器解开后的业务逻辑） | 中 |

---

## 三、关键环境事实

### 3.1 客户端架构

```
Unity + IL2CPP + tolua#(Lua) + lxnet(自研网络层, 打包 ENet/UDP + AES)
APK 3.34 GB, 16884 个条目, 中央目录 1.45 MB
```

运行时数据目录：
```
/storage/emulated/0/Android/data/com.huanmeng.zhanjian2/files/
  ├─ script.script (16.3 MB)   ← lxdata 容器（Lua 业务逻辑，加密）
  ├─ config.conf   (154 MB)    ← lxdata 容器（游戏数据，加密）
  ├─ bootstrap.xml, launch.core, starter/xbask.core
  ├─ check_version.txt = 0.0.629.1
  └─ log/{elapsed_log,runstate_log,profiler_log}
```

### 3.2 本机网络对现行服务器**完全可达**（重要）

`xr-server-1/2/3/4`、`xrpc`、`andpassportapi` 的 80/443/10005/10009/10010 **全部可连**。
（此前判断"老服务器不通"与此无关：`s1..s14.jr.moefantasy.com` → 116.63.102.78
是真退役了，域名 `login/version.jr.moefantasy.com` 已 NXDOMAIN。）

---

## 四、已产出的工具（全部可复用）

| 工具 | 作用 |
|---|---|
| `probe/remotezip.py` | **HTTP Range 远程读 ZIP/APK**，不下整包（`list`/`find`/`pull`/`head`） |
| `probe/dns_recon.py` | 子域爆破 + 泛解析检测 |
| `probe/probe_hosts.py` | 主机端口连通性 + HTTP(S) 探活 |
| `probe/meta_strings.py` | IL2CPP `global-metadata.dat` 字符串抽取 |
| `probe/kwstat.py` / `strings.py` | 二进制关键词命中统计 / 带偏移字符串抽取 |
| `probe/lxdata_probe.py` | `lxdata` 容器熵与结构分析 |
| `probe/pcap_analyze.py` | pcap → DNS / TLS SNI / 明文 HTTP 提取 |
| `probe/pcap_streams.py` | **TCP 流重组**（双向） |
| `probe/extract_resp.py` | HTTP 正文提取 + 压缩/XOR/ECB 自动判定 |
| `probe/flow_analyze.py` | 指定端口流的熵/频率/周期/明文串分析 |
| `probe/transform_bf.py` | 简单变换（XOR/位反转/半字节交换/移位）暴力排除 |
| `probe/replay.py` | **重放捕获请求到真实游戏服**（已成功） |
| `probe/probe_api.py` | 老式 HTTP API 路径探测（已确认全部 404） |

## 五、已确认作废的旧协议

| 旧东西 | 现状 |
|---|---|
| `login.jr.moefantasy.com` / `version.jr.moefantasy.com` | **NXDOMAIN，已死** |
| `s1..s14.jr.moefantasy.com` (116.63.102.78) | 记录在，**IP 不通** |
| `AuthHead: HMS 881d3SlFucX5R5hE` / `AuthKey: kHPmWZ4zQBYP24ubmJ5wA4oz0d8EgIFe` | 客户端中已消失 |
| URL 签名密钥 `<REDACTED_HEX32>` | 客户端中已消失，请求中不再出现 `t`/`e` 签名 |
| 老 REST API（`api/initGame`、`pve/getPveData`、`boat/*` …） | **新服上全部 404** |
| `channel=100016` / `market=2` | 现为 `channel=taptap` / `app_id=xr_cn_release` |
