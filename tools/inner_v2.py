# -*- coding: utf-8 -*-
"""
内层解析 v2 —— 用「msgid 落在 0x1b00..0x1bff」这一强约束切分内层消息

依据 (全部实测确认):
  游戏层消息号都在 0x1bxx:
    0x1b5f=7007  0x1b64=7012  0x1b6a=7018  0x1bb3=7091
    0x1b62=7010  0x1b6e=7022  0x1bdb=7131  0x1be0=7136
    0x1be1=7137  0x1be2=7138
  服务端外层消息号在别的区段 (3397/5957/9543/11589/27205...), 因此该约束能干净区分。

切分规则:
  扫描 u16 == 0x1bxx 的位置作为消息起点; 到下一条 0x1bxx 起点为止即为本消息内容.
"""
import collections
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wsgr import proto

CAP = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "capture"))
INNER_LO, INNER_HI = 0x1B00, 0x1BFF


def split_inner(body):
    """按 0x1bxx 起点切分内层消息."""
    starts = []
    for i in range(len(body) - 1):
        v = struct.unpack_from("<H", body, i)[0]
        if INNER_LO <= v <= INNER_HI:
            starts.append((i, v))
    # 相邻过近的起点多半是误命中: 要求间隔 >= 3
    clean = []
    for pos, mid in starts:
        if clean and pos - clean[-1][0] < 3:
            continue
        clean.append((pos, mid))
    out = []
    for k, (pos, mid) in enumerate(clean):
        end = clean[k + 1][0] if k + 1 < len(clean) else len(body)
        out.append((pos, mid, body[pos + 2:end]))
    return out


def varint_at(b, i):
    v, shift, j = 0, 0, i
    while j < len(b):
        c = b[j]
        j += 1
        v |= (c & 0x7F) << shift
        if not (c & 0x80):
            return v, j
        shift += 7
        if shift > 63:
            return None, i
    return None, i


def parse_fields(b, maxlen=64):
    """尽力 TLV 解析, 失败即停."""
    fields, i = [], 0
    while i < len(b):
        tag, j = varint_at(b, i)
        if tag is None or tag == 0:
            break
        f, wt = tag >> 3, tag & 7
        if f == 0 or f > 100000:
            break
        if wt == 0:
            v, k = varint_at(b, j)
            if v is None:
                break
            fields.append((f, 0, v))
            i = k
        elif wt == 2:
            ln, k = varint_at(b, j)
            if ln is None or k + ln > len(b):
                break
            fields.append((f, 2, b[k:k + ln]))
            i = k + ln
        elif wt == 5:
            if j + 4 > len(b):
                break
            fields.append((f, 5, b[j:j + 4]))
            i = j + 4
        elif wt == 1:
            if j + 8 > len(b):
                break
            fields.append((f, 1, b[j:j + 8]))
            i = j + 8
        else:
            break
        if len(fields) >= maxlen:
            break
    return fields


def main():
    allcnt = collections.Counter()
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
            msgs = split_inner(body)
            cov = sum(len(m[2]) for m in msgs)
            print("\n--- 帧 off=%d len=%d : %d 条内层消息, 覆盖 %d/%d (%.1f%%)"
                  % (off, ln, len(msgs), cov, len(body), 100.0 * cov / max(1, len(body))))
            cnt = collections.Counter(m[1] for m in msgs)
            allcnt.update(cnt)
            for mid, c in cnt.most_common(12):
                allcnt[mid] += 0
                print("      msgid=%-6d (0x%04x)  x%d" % (mid, mid, c))
            print("    样本:")
            for pos, mid, c in msgs[:6]:
                f = parse_fields(c)
                print("      @%-6d msgid=%-6d 内容 %-4d 字节, TLV 解出 %d 字段 %s"
                      % (pos, mid, len(c), len(f),
                         [(x[0], x[1], x[2] if x[1] != 2 else len(x[2])) for x in f[:6]]))
    print("\n" + "=" * 84)
    print("### 两份抓包合计出现的内层 msgid")
    for mid, c in allcnt.most_common(40):
        print("  0x%04x  %-6d  x%d" % (mid, mid, c))


if __name__ == "__main__":
    main()
