# -*- coding: utf-8 -*-
"""解码 pcap 中某个端口的双向帧 (用于对照真机客户端的行为)."""
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wsgr import proto
from pcap_streams import read_pcap, parse_eth, parse_ip


def main():
    pcap = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 10010
    linktype, pkts = read_pcap(pcap)
    pkts.sort(key=lambda x: x[0])
    flows = collections.defaultdict(lambda: {"a": [], "b": []})
    for ts, pkt in pkts:
        et, pl = parse_eth(pkt, linktype)
        if not pl:
            continue
        v, pr, src, dst, ip = parse_ip(pl, et)
        if pr != 6 or not ip or len(ip) < 20:
            continue
        doff = (ip[12] >> 4) * 4
        sp, dp = struct.unpack_from("!HH", ip, 0)
        if port not in (sp, dp):
            continue
        seq = struct.unpack_from("!I", ip, 4)[0]
        pay = ip[doff:]
        if not pay:
            continue
        key = tuple(sorted([(src, sp), (dst, dp)]))
        side = "a" if (src, sp) == key[0] else "b"
        flows[key][side].append((seq, ts, pay))

    for key, f in flows.items():
        for side, label in (("a", "客户端->服务端"), ("b", "服务端->客户端")):
            segs = sorted(f[side], key=lambda x: x[0])
            if not segs:
                continue
            blob = b"".join(p for _, _, p in segs)
            print("=" * 78)
            print("### %s  %s  %d 字节" % (key[0], label, len(blob)))
            plain = proto.decrypt(blob)
            for off, ln, c in proto.parse_frames(plain, 0):
                mid = proto.msgid_of(c)
                seqv = proto.seq_of(c)
                if ln > 300:
                    print("  off=%-6d len=%-6d msgid=%-6d (大帧, 略)"
                          % (off, ln, mid))
                    continue
                print("  off=%-6d len=%-5d msgid=%-6d seq=%-6s hex=%s"
                      % (off, ln, mid, seqv, c.hex(" ")[:78]))


if __name__ == "__main__":
    main()
