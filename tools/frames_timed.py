# -*- coding: utf-8 -*-
"""
带时间戳的逐帧解码: 把客户端->服务端流按序重组, 为每一帧标注"完成该帧的包"的时间.
用于把消息 ID 与操作动作对齐 (差集法/时间对齐法).

用法: python frames_timed.py <pcap> [port]
"""
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pcap_streams import read_pcap, parse_eth, parse_ip
from wsgr_proto import decrypt, parse_frames


def main():
    pcap = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 10010
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
        flows[key][side].append((seq, ts, payload))

    for key, f in flows.items():
        # 只处理"客户端->服务端"方向: 先看方向 a 的字节量, 取小的那侧作为客户端请求
        for side, label in (("a", "A->B"), ("b", "B->A")):
            segs = f[side]
            if not segs:
                continue
            segs.sort(key=lambda x: x[0])
            blob = b"".join(p for _, _, p in segs)
            if len(blob) > 4000:
                continue          # 只看小的一侧 (客户端请求)
            plain = decrypt(blob)
            # 计算每个字节偏移对应的完成时间
            time_at = []
            for _, ts, p in segs:
                time_at.extend([ts] * len(p))
            fr, used, sk = parse_frames(plain, 0)
            if not fr:
                continue
            t0 = segs[0][1]
            print("=" * 88)
            print("### %s:%d  %s  %d 字节 -> %d 帧" % (key[0][0], key[0][1], label, len(blob), len(fr)))
            for off, ln, c in fr:
                end = min(off + ln - 1, len(time_at) - 1)
                t = time_at[end] if time_at else t0
                mid = c[:2].hex(" ") if len(c) >= 2 else ""
                msgid = struct.unpack_from("<H", c, 0)[0] if len(c) >= 2 else -1
                hexs = c.hex(" ")
                asc = "".join(chr(x) if 32 <= x < 127 else "." for x in c)
                print("  t+%7.3fs  off=%-5d len=%-5d msgid=%-6d %-40s %s"
                      % (t - t0, off, ln, msgid, hexs[:76], asc[:44]))
            print()


if __name__ == "__main__":
    main()
