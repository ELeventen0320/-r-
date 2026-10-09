# -*- coding: utf-8 -*-
"""
从 pC.pcap 提取真机登录块作为新模板, 并打印其字段结构.
模板含 token, 保存在 capture/ (已被 .gitignore 排除), 绝不提交.
"""
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wsgr import proto
from pcap_streams import read_pcap, parse_eth, parse_ip

CAP = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "capture"))
PCAP = os.path.join(CAP, "pC.pcap")
OUT = os.path.join(CAP, "login_template.bin")


def client_stream(pcap, port=10010):
    lt, pkts = read_pcap(pcap)
    pkts.sort(key=lambda x: x[0])
    flows = collections.defaultdict(list)
    for ts, pkt in pkts:
        et, pl = parse_eth(pkt, lt)
        if not pl:
            continue
        v, pr, src, dst, ip = parse_ip(pl, et)
        if pr != 6 or not ip or len(ip) < 20:
            continue
        sp, dp = struct.unpack_from("!HH", ip, 0)
        if port not in (sp, dp):
            continue
        seq = struct.unpack_from("!I", ip, 4)[0]
        pay = ip[(ip[12] >> 4) * 4:]
        if not pay:
            continue
        key = tuple(sorted([(src, sp), (dst, dp)]))
        side = "a" if (src, sp) == key[0] else "b"
        if side == "a":
            flows[key].append((seq, pay))
    best, n = b"", 10 ** 9
    for key, segs in flows.items():
        segs.sort(key=lambda x: x[0])
        blob = b"".join(p for _, p in segs)
        if 0 < len(blob) < n:
            best, n = blob, len(blob)
    return best


def main():
    c2s = client_stream(PCAP)
    print("客户端流 %d 字节" % len(c2s))
    plain = proto.decrypt(c2s)
    open(OUT, "wb").write(c2s)
    print("模板已保存: %s" % OUT)
    print()
    for off, ln, content in proto.parse_frames(plain, 0):
        mid = proto.msgid_of(content)
        seqv = proto.seq_of(content)
        print("--- off=%-5d len=%-5d msgid=%-6d seq=%s" % (off, ln, mid, seqv))
        if ln > 20:
            # 打印字段
            body = content[2:len(content) - 4] if seqv is not None else content[2:]
            i = 0
            while i < len(body) - 1:
                tag = body[i]
                f, wt = tag >> 3, tag & 7
                if wt == 0:
                    v, j2 = proto.rd_varint(body, i + 1)
                    print("      f%-4d varint = %s" % (f, v))
                    i = j2
                elif wt == 2:
                    ln2, j2 = proto.rd_varint(body, i + 1)
                    if ln2 is None or j2 + ln2 > len(body):
                        print("      (解析中断 @%d)" % i)
                        break
                    data = body[j2:j2 + ln2]
                    vis = "".join(chr(c) if 32 <= c < 127 else "." for c in data[:40])
                    print("      f%-4d len=%-4d %s | %s" % (f, ln2, data[:24].hex(" "), vis))
                    i = j2 + ln2
                else:
                    print("      (未知 wiretype %d @%d) 余下: %s"
                          % (wt, i, body[i:i + 20].hex(" ")))
                    break


if __name__ == "__main__":
    main()
