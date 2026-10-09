# -*- coding: utf-8 -*-
"""
内层容器统计反推

思路:
  不在手工猜边界, 而是扫描大帧中所有"看起来像内层消息头"的位置
  (u16 msgid + 合法 tag), 统计 msgid 频次与相邻间距,
  用统计规律反推容器格式 (是否长度前缀 / 记录如何分隔).

合法 protobuf tag 的判据: 低 3 位是合法 wiretype (0,1,2,5),
且字段号不为 0; 长度前缀型 (wt=2) 的后续长度不能越界.
"""
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wsgr import proto

CAP = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "capture"))

# 已确认的内层消息号
KNOWN_INNER = {0x1BDB: "远征状态", 0x1BE2: "?", 0x1BE1: "领取回执", 0x1BE0: "领取请求"}


def varint_at(b, i, limit=None):
    v, shift, j = 0, 0, i
    end = len(b) if limit is None else min(limit, len(b))
    while j < end:
        c = b[j]
        j += 1
        v |= (c & 0x7F) << shift
        if not (c & 0x80):
            return v, j
        shift += 7
        if shift > 63:
            return None, i
    return None, i


def try_parse_message(b, i, end):
    """尝试从 i 解析一条 <u16 msgid><字段...> 消息.

    返回 (msgid, 消费的字节数, 字段列表) 或 None.
    字段解析到无法继续为止; 要求至少解析出 1 个字段.
    """
    if i + 3 > end:
        return None
    mid = struct.unpack_from("<H", b, i)[0]
    if mid == 0 or mid > 40000:
        return None
    j = i + 2
    fields = []
    while j < end:
        # 遇到下一个"像消息头"的位置就停 (u16 + 合法 tag)
        if len(fields) > 0 and j + 3 <= end:
            nxt = struct.unpack_from("<H", b, j)[0]
            if 1 <= nxt <= 40000:
                wt = b[j + 2] & 7
                if wt in (0, 1, 2, 5) and (b[j + 2] >> 3) != 0:
                    break
        tag, j2 = varint_at(b, j, end)
        if tag is None or tag == 0:
            break
        f, wt = tag >> 3, tag & 7
        if f == 0 or f > 2000:
            break
        if wt == 0:
            v, j3 = varint_at(b, j2, end)
            if v is None:
                break
            fields.append((f, 0, v))
            j = j3
        elif wt == 2:
            ln, j3 = varint_at(b, j2, end)
            if ln is None or j3 + ln > end:
                break
            fields.append((f, 2, b[j3:j3 + ln]))
            j = j3 + ln
        elif wt == 5:
            if j2 + 4 > end:
                break
            fields.append((f, 5, b[j2:j2 + 4]))
            j = j2 + 4
        elif wt == 1:
            if j2 + 8 > end:
                break
            fields.append((f, 1, b[j2:j2 + 8]))
            j = j2 + 8
        else:
            break
    if not fields:
        return None
    return mid, j - i, fields


def main():
    for sub, name in (("f10010", "10.0.2.15_C_S_53568.bin"),
                      ("f3", "10.0.2.15_C_S_58340.bin")):
        path = os.path.join(CAP, sub, name)
        if not os.path.exists(path):
            continue
        plain = proto.decrypt(open(path, "rb").read())
        print("=" * 84)
        print("### %s" % name)
        for off, ln, content in proto.parse_frames(plain, 8):
            if ln < 1000:
                continue
            body = content[2:]
            n = len(body)
            # 全位置扫描: 记录所有能解析成消息的起点
            msgs = []
            i = 0
            while i < n - 4:
                r = try_parse_message(body, i, n)
                if r and r[1] >= 4:
                    msgs.append((i,) + r)
                    i += r[1]          # 跳到下一条
                else:
                    i += 1
            print("\n--- 帧 off=%d len=%d  解析出 %d 条内层消息, 覆盖 %d/%d 字节 (%.1f%%)"
                  % (off, ln, len(msgs), sum(m[2] for m in msgs), n,
                     100.0 * sum(m[2] for m in msgs) / n))
            cnt = collections.Counter(m[1] for m in msgs)
            print("    msgid 频次 (前 20):")
            for mid, c in cnt.most_common(20):
                tag = KNOWN_INNER.get(mid, "")
                print("      0x%04x %-6d x%-5d %s" % (mid, mid, c, tag))
            print("    前 12 条消息 (起点, msgid, 长度, 字段数):")
            for pos, mid, used, fields in msgs[:12]:
                print("      @%-6d msgid=%-6d used=%-5d 字段=%d %s"
                      % (pos, mid, used, len(fields),
                         [(f, w) for f, w, _ in fields[:6]]))
        print()


if __name__ == "__main__":
    main()
