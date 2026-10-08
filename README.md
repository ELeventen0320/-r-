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
| 脱机连接游戏服 | ✅ **已重放成功**（本机直连拿到真实响应） |
| 游戏主协议编解码 | ❌ **未完成**（二进制，最高位像标记位 / 轻量混淆，非强加密） |

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

## 四、待完成：游戏主协议编解码

响应数据**不是强加密**，判断依据：

1. 存在高度规整的重复块（16~17 字节），例如响应中重复约 10 次：
   `bf ae ae ae eb a3 a8 ae ae ae 2e a8 ae ae ae af ae`
2. 大量字节成对只差最高位：`AE/2E`、`A8/28`、`AF/2F`、`BF/3F`、`A3/23`
3. 固定明文（12 字节首包）在**两次不同连接中密文完全相同** → 无每连接 IV / 密钥流
4. 重复周期检测未发现短周期 XOR 密钥

**当前假设**：最高位作标记位的自定义位打包序列化（类 varint / BitStream），
或 `lxnet` 的轻量流密码。需要拿到编解码器本体。

三条可行路线：

| 路线 | 做法 | 成本 |
|---|---|---|
| **A（推荐）** | Frida hook `libtolua.so` 的 `lxnet::Socketer::SendData`（已确认是**导出符号**）与接收侧，dump 明文 | 低-中 |
| B | 静态逆向 `libtolua.so` 的 `packet_*` / `lxnet::Socketer`（需 IDA/Ghidra） | 中-高 |
| C | 从进程内存 dump 解密后的 Lua（`lxdata` 容器解开后的业务逻辑） | 中 |

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
| URL 签名密钥 `ade2688f1904e9fb8d2efdb61b5e398a` | 已从客户端移除，请求不再带 `t`/`e` |
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
