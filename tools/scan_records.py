# -*- coding: utf-8 -*-
"""
内层编码分析: 从服务端大帧里提取"远征记录"这类重复结构.

已知模式 (手工分析得到):
    记录 = <len><字段...>
    字段 = 08 <舰队> | 18 <远征ID> | 10 <时间戳>
即  0b 08 06 18 91 4e 10 8f c3 c1 cb 06
    len=11, 舰队=6, 远征=10001, 时间戳=<varint>

本脚本扫描所有大帧, 用"重复出现 18 <id> 10 <ts>"这一特征定位记录,
并回溯最近的长度前缀来切分记录.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wsgr import proto

CAP = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "capture"))


def varint_at(b, i):
    v, shift = 0, 0
    j = i
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


def scan_records(buf, min_hits=2):
    """找 (18 <varint>) 后紧跟 (10 <varint>) 的位置."""
    hits = []
    i = 0
    n = len(buf)
    while i < n - 2:
        if buf[i] == 0x18:
            v1, j = varint_at(buf, i + 1)
            if v1 is not None and j < n - 1 and buf[j] == 0x10:
                v2, k = varint_at(buf, j + 1)
                if v2 is not None:
                    hits.append((i, v1, v2, k))
                    i = k
                    continue
        i += 1
    return hits


def main():
    files = [
        ("f3", "10.0.2.15_C_S_58340.bin"),
        ("f10010", "10.0.2.15_C_S_53568.bin"),
    ]
    for sub, name in files:
        path = os.path.join(CAP, sub, name)
        if not os.path.exists(path):
            continue
        plain = proto.decrypt(open(path, "rb").read())
        print("=" * 80)
        print("### %s" % name)
        for off, ln, content in proto.parse_frames(plain, 8):
            if ln < 1000:
                continue
            mid = proto.msgid_of(content)
            body = content[2:]
            hits = scan_records(body)
            print("\n--- 帧 off=%d len=%d msgid=%d : 找到 %d 处 (18 id, 10 ts) 模式"
                  % (off, ln, mid, len(hits)))
            for (pos, eid, ts, end) in hits[:14]:
                # 回溯: 往前找 08 <fleet>, 再看更前一个字节是否为长度前缀
                fleet = None
                back = pos - 2
                if back >= 1 and body[back] == 0x08:
                    fv, _ = varint_at(body, back + 1)
                    fleet = fv
                lenpre = body[pos - 3] if pos >= 3 else None
                span = end - (pos - 3)
                print("   @%-5d 远征=%-7d 时间戳=%-12d 舰队=%-4s 前置字节=%-4s 记录长=%d"
                      % (pos, eid, ts, fleet,
                         ("0x%02x" % lenpre) if lenpre is not None else "-", span))
            # 时间戳转日期, 便于判断含义
            for (pos, eid, ts, end) in hits[:3]:
                try:
                    import time as _t
                    print("      -> 远征 %d 时间戳 %d = %s"
                          % (eid, ts, _t.strftime("%Y-%m-%d %H:%M:%S", _t.gmtime(ts))))
                except Exception:
                    pass


if __name__ == "__main__":
    main()
