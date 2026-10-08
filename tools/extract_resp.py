# -*- coding: utf-8 -*-
"""
从 pcap 中提取 HTTP 响应正文, 落盘并做结构/密码分析.
"""
import collections
import math
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_streams import read_pcap, parse_eth, parse_ip


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def analyze(name, body):
    print("=" * 90)
    print("### %s   (%d bytes)" % (name, len(body)))
    print("  entropy = %.4f / 8.0" % entropy(body))
    print("  head32  = %s" % body[:32].hex(" "))
    print("  ascii   = %s" % "".join(chr(c) if 32 <= c < 127 else "." for c in body[:64]))

    # 常见压缩格式
    for label, magic in (("gzip", b"\x1f\x8b"), ("zlib", b"\x78"), ("bz2", b"BZh"),
                         ("lzma", b"\xfd7zXZ"), ("zstd", b"\x28\xb5\x2f\xfd"), ("lz4?", b"\x04\x22\x4d\x18")):
        if body.startswith(magic):
            print("  !! 魔数匹配: %s" % label)
    for label, fn in (("zlib", zlib.decompress), ("gzip", lambda d: zlib.decompress(d, 47)),
                      ("raw-deflate", lambda d: zlib.decompress(d, -15))):
        try:
            out = fn(body)
            print("  !! %s 解压成功 -> %d 字节: %s" % (label, len(out), out[:120]))
        except Exception:
            pass
    # 单字节 XOR
    for k in range(1, 256):
        d = bytes(b ^ k for b in body[:256])
        if b"{" in d or b"error" in d or b"data" in d:
            ratio = sum(1 for c in d if 32 <= c < 127) / len(d)
            if ratio > 0.9:
                print("  ?? 单字节 XOR key=0x%02x -> %s" % (k, d[:100]))
    # ECB 重复块检测 (16 字节)
    if len(body) >= 64:
        blocks = [body[i:i + 16] for i in range(0, len(body) - 15, 16)]
        dup = len(blocks) - len(set(blocks))
        print("  16字节块重复数 = %d / %d (ECB 特征)" % (dup, len(blocks)))
    # 是否存在明文片段
    printable_runs = []
    cur = bytearray()
    for b in body:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= 8:
                printable_runs.append(cur.decode())
            cur = bytearray()
    if len(cur) >= 8:
        printable_runs.append(cur.decode())
    if printable_runs:
        print("  内部明文串: %s" % printable_runs[:6])


def main():
    pcap = sys.argv[1]
    outdir = sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    linktype, pkts = read_pcap(pcap)
    pkts.sort(key=lambda x: x[0])

    flows = collections.defaultdict(lambda: {"a": [], "b": []})
    for ts, pkt in pkts:
        etype, pl = parse_eth(pkt, linktype)
        if not pl:
            continue
        v, proto, src, dst, ip = parse_ip(pl, etype)
        if proto != 6 or not ip or len(ip) < 20:
            continue
        doff = (ip[12] >> 4) * 4
        sport, dport = struct.unpack_from("!HH", ip, 0)
        seq = struct.unpack_from("!I", ip, 4)[0]
        payload = ip[doff:]
        if not payload:
            continue
        key = tuple(sorted([(src, sport), (dst, dport)]))
        side = "a" if (src, sport) == key[0] else "b"
        flows[key][side].append((seq, payload))

    idx = 0
    for key, f in flows.items():
        for side, label in (("a", "req"), ("b", "resp")):
            blob = b"".join(c[1] for c in sorted(f[side], key=lambda x: x[0]))
            if b"HTTP/1." not in blob:
                continue
            head, _, body = blob.partition(b"\r\n\r\n")
            if not body:
                continue
            idx += 1
            fname = os.path.join(outdir, "%02d_%s_%s_%d.bin" % (idx, key[0][0].replace(".", "_"), label, key[0][1]))
            with open(fname, "wb") as fh:
                fh.write(body)
            host = ""
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"host:"):
                    host = line.split(b":", 1)[1].strip().decode("latin-1")
            analyze("%s %s:%d -> %s" % (label.upper(), key[0][0], key[0][1], host), body)
    print("\n共导出 %d 个正文到 %s" % (idx, outdir))


if __name__ == "__main__":
    main()
