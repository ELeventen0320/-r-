# -*- coding: utf-8 -*-
"""
提取指定端口的 TCP 流负载并做协议分析:
字节分布 / 熵 / zlib / 明文串 / 重复周期(XOR 密钥长度探测) / 异或还原尝试
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


def strings_of(b, minlen=5, limit=40):
    out, cur = [], bytearray()
    for x in b:
        if 32 <= x < 127:
            cur.append(x)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode())
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode())
    return out[:limit]


def best_period(b, maxp=64):
    """用重合指数找最小重复周期(近似 XOR 密钥长度)."""
    res = []
    for p in range(1, maxp + 1):
        same = 0
        tot = 0
        for i in range(len(b) - p):
            tot += 1
            if b[i] == b[i + p]:
                same += 1
        res.append((same / max(1, tot), p))
    res.sort(reverse=True)
    return res[:6]


def main():
    pcap = sys.argv[1]
    port = int(sys.argv[2])
    outdir = sys.argv[3]
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
        if port not in (sport, dport):
            continue
        seq = struct.unpack_from("!I", ip, 4)[0]
        payload = ip[doff:]
        if not payload:
            continue
        key = tuple(sorted([(src, sport), (dst, dport)]))
        side = "a" if (src, sport) == key[0] else "b"
        flows[key][side].append((seq, payload))

    log = open(os.path.join(outdir, "flow_analysis.txt"), "w", encoding="utf-8")

    def P(*a):
        print(*a)
        print(*a, file=log)

    for key, f in sorted(flows.items(), key=lambda kv: -sum(len(p) for _, p in kv[1]["a"] + kv[1]["b"])):
        for side, label in (("a", "S->C"), ("b", "C->S")):
            blob = b"".join(c[1] for c in sorted(f[side], key=lambda x: x[0]))
            if not blob:
                continue
            fn = os.path.join(outdir, "%s_%s_%d.bin" % (key[0][0], label.replace("->", "_"), key[0][1]))
            with open(fn, "wb") as fh:
                fh.write(blob)
            P("=" * 90)
            P("### %s %s:%d  %d bytes -> %s" % (label, key[0][0], key[0][1], len(blob), os.path.basename(fn)))
            P("  entropy = %.4f" % entropy(blob))
            P("  head64  = %s" % blob[:64].hex(" "))
            hist = collections.Counter(blob).most_common(8)
            P("  字节频率Top8 = %s" % ", ".join("%02x:%d(%.1f%%)" % (k, v, 100 * v / len(blob)) for k, v in hist))
            for lbl, fnc in (("zlib", zlib.decompress), ("gzip", lambda d: zlib.decompress(d, 47)),
                             ("raw", lambda d: zlib.decompress(d, -15))):
                try:
                    dec = fnc(blob)
                    P("  !! %s OK -> %d bytes" % (lbl, len(dec)))
                    open(os.path.join(outdir, os.path.basename(fn) + "." + lbl), "wb").write(dec)
                except Exception:
                    pass
            P("  明文串 = %s" % strings_of(blob, 6, 12))
            P("  重复周期Top = %s" % ["%.4f@p%d" % (s, p) for s, p in best_period(blob[:65536])])
    log.close()
    P("\n输出目录: %s" % outdir)


if __name__ == "__main__":
    main()
