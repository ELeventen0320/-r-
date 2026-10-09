# -*- coding: utf-8 -*-
"""打印远征记录附近的原始字节, 用于确定真实记录结构."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wsgr import proto

CAP = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "capture"))


def dump(tag, buf, center, before=48, after=96):
    s = max(0, center - before)
    e = min(len(buf), center + after)
    print("--- %s  (中心 @%d) ---" % (tag, center))
    for base in range(s, e, 16):
        chunk = buf[base:base + 16]
        hexs = " ".join("%02x" % c for c in chunk)
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        mark = " <<<" if base <= center < base + 16 else ""
        print("  @%-6d %-47s %s%s" % (base, hexs, asc, mark))
    print()


for sub, name, positions in (
        ("f10010", "10.0.2.15_C_S_53568.bin", [2555, 2571, 2580]),
        ("f3", "10.0.2.15_C_S_58340.bin", [2546, 2558, 2571])):
    path = os.path.join(CAP, sub, name)
    if not os.path.exists(path):
        continue
    plain = proto.decrypt(open(path, "rb").read())
    for off, ln, content in proto.parse_frames(plain, 8):
        if off != 251:
            continue
        body = content[2:]
        print("=" * 78)
        print("### %s  帧 off=251 len=%d" % (name, ln))
        # 以第一条记录的起点为中心
        dump("记录区起点前", body, positions[0] - 3, before=64, after=64)
        break
