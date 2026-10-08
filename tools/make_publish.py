# -*- coding: utf-8 -*-
"""
准备可公开发布的仓库内容:
1) 从工程目录复制工具脚本
2) 对文档做敏感信息脱敏
3) 绝不复制含凭据的目录 (device/ capture/ apk/)

脱敏清单从同目录的 secrets.txt 读取 (每行 `真实值=占位符`),
该文件**不入库**, 以免把敏感值本身写进代码。

运行后产出 <工程根>/publish/
"""
import os
import re
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))   # probe/ 的上一级 = 工程根
PUB = os.path.join(ROOT, "publish")
TOOLS_SRC = os.path.join(ROOT, "probe")

# 从外部清单加载脱敏规则
SECRETS = []
_secrets_file = os.path.join(HERE, "secrets.txt")
if os.path.exists(_secrets_file):
    with open(_secrets_file, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#") or "=" not in line:
                continue
            real, ph = line.split("=", 1)
            SECRETS.append((real, ph))

TOOLS = [
    "remotezip.py", "dns_recon.py", "probe_hosts.py", "meta_strings.py",
    "kwstat.py", "strings.py", "lxdata_probe.py", "analyze_entries.py",
    "pcap_analyze.py", "pcap_streams.py", "extract_resp.py", "dump_bodies.py",
    "flow_analyze.py", "transform_bf.py", "replay.py", "probe_api.py",
    "mem_find.py", "elf_syms.py", "scan_mem.sh", "scan_mem2.sh",
    # --- 协议破译相关 ---
    "wsgr_client.py",      # ★ 脱机客户端原型 (XOR 0xAE + 帧 + TLV)
    "decode_proto.py",     # 批量解密并切帧
    "decode_full.py",      # 解码 73KB 初始数据 + TLV 字段扫描
    "msgpack_try.py",      # MessagePack 试探 (已排除)
    "disasm.py",           # ARM64 反汇编 + 调用图 (capstone)
    "dynsym_dump.py",      # .dynsym 完整转储
    "ks_period.py",        # 密钥流周期探测
    "lxdata_xor.py",       # lxdata 文件间 XOR 对比
    "lxdata_decrypt.py",   # lxdata 单字节 XOR 全空间试探
    "reg_analyze.py",      # 内存区域内容分析
    "scan_offset.sh",      # 区域内按偏移定位关键词
    "dump_msgs.py",         # 消息转储 (头+TLV)
    "wsgr_proto.py",        # ★ 协议编解码库 (加解密+切帧+跳填充)
    "frames_hex.py",         # 逐帧十六进制转储 (识别动作消息)
    "wsgr_headless.py",     # ★ 脱机客户端完整链路 (列表+认证+连接)
    "frame_verify.py",      # 帧格式验证
    "frame_verify2.py",     # 帧格式验证 (带重同步)
    "frame_solve.py",       # 帧格式穷举求解
    "hd.py",                # 带偏移 hexdump
]

DOCS = [
    "舰R现行协议还原报告.md",
    "舰R脱机脚本复活_调研报告.md",
]

# 额外脱敏后写入 publish 根目录: (工程根下的源文件, publish 内的目标名)
EXTRA = [
    ("README.publish.md", "README.md"),
]


def scrub(text):
    hits = []
    for real, ph in SECRETS:
        if real and real in text:
            hits.append("%s x%d" % (ph, text.count(real)))
            text = text.replace(real, ph)
    # 兜底: 32 位十六进制 token 形态 / 19 位纯数字 ID
    text = re.sub(r"\b[0-9a-f]{32}\b", "<REDACTED_HEX32>", text)
    text = re.sub(r"\b1[0-9]{18}\b", "<REDACTED_ID19>", text)
    return text, hits


def rmtree_force(path):
    """删除目录, 遇到只读文件先清属性 (不触碰 publish/.git)."""
    import stat

    def onerr(func, p, exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass

    if os.path.exists(path):
        shutil.rmtree(path, onerror=onerr)


def main():
    print("脱敏规则条数: %d (%s)" % (len(SECRETS), "已加载 secrets.txt" if SECRETS else "缺失!"))
    # 只清理产物目录, 保留 .git / README / .gitignore
    rmtree_force(os.path.join(PUB, "docs"))
    rmtree_force(os.path.join(PUB, "tools"))
    os.makedirs(os.path.join(PUB, "docs"), exist_ok=True)
    os.makedirs(os.path.join(PUB, "tools"), exist_ok=True)

    for t in TOOLS:
        src = os.path.join(TOOLS_SRC, t)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(PUB, "tools", t))
            print("tool   %s" % t)
        else:
            print("MISS   %s" % t)

    for d in DOCS:
        src = os.path.join(ROOT, d)
        if not os.path.exists(src):
            print("MISS doc %s" % d)
            continue
        with open(src, encoding="utf-8") as f:
            txt = f.read()
        txt2, hits = scrub(txt)
        with open(os.path.join(PUB, "docs", d), "w", encoding="utf-8") as f:
            f.write(txt2)
        print("doc    %s   脱敏: %s" % (d, hits or "无"))

    for src_name, dst_name in EXTRA:
        src = os.path.join(ROOT, src_name)
        if not os.path.exists(src):
            print("MISS   %s" % src_name)
            continue
        with open(src, encoding="utf-8") as f:
            txt = f.read()
        txt2, hits = scrub(txt)
        with open(os.path.join(PUB, dst_name), "w", encoding="utf-8") as f:
            f.write(txt2)
        print("extra  %s -> %s   脱敏: %s" % (src_name, dst_name, hits or "无"))

    print("\npublish 目录: %s" % PUB)
    print("提示: 还需手动拷入 .gitignore 与 tools/make_publish.py")


if __name__ == "__main__":
    main()
