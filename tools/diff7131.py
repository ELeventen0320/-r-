# -*- coding: utf-8 -*-
"""聚焦: 7131 (远征状态) 的双样本逐字节对齐."""
import difflib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wsgr import proto, state

CAP = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "capture"))
SRC = [("A(f10010)", "f10010", "10.0.2.15_C_S_53568.bin"),
       ("B(f3)", "f3", "10.0.2.15_C_S_58340.bin")]


def get7131(sub, name):
    p = os.path.join(CAP, sub, name)
    plain = proto.decrypt(open(p, "rb").read())
    for off, ln, content in proto.parse_frames(plain, 8):
        if ln < 1000:
            continue
        for pos, mid, c in state.split_inner(content[2:]):
            if mid == 0x1BDB:
                return c
    return None


def annotate(b, label):
    print("\n%s  (%d 字节)" % (label, len(b)))
    # 用已知的锚点标出记录
    print("  hex   : %s" % b.hex(" "))
    # 标出 18 <id> 10 <val> 三元组
    marks = []
    i = 0
    while i < len(b) - 3:
        if b[i] == 0x18:
            eid, j = state.varint_at(b, i + 1)
            if eid and 10000 <= eid <= 99999 and j < len(b) and b[j] == 0x10:
                val, k = state.varint_at(b, j + 1)
                marks.append(("[%d:%d]" % (i, k), "远征%d 值%d" % (eid, val)))
                i = k
                continue
        i += 1
    for span, desc in marks:
        print("  记录 %-10s %s" % (span, desc))
    return marks


a = get7131(SRC[0][1], SRC[0][2])
bb = get7131(SRC[1][1], SRC[1][2])
if a is None or bb is None:
    print("未取到 7131")
    sys.exit(0)

annotate(a, SRC[0][0])
annotate(bb, SRC[1][0])

print("\n=== 逐字节对齐 (difflib) ===")
sm = difflib.SequenceMatcher(a=a, b=bb, autojunk=False)
for tag, i1, i2, j1, j2 in sm.get_opcodes():
    if tag == "equal":
        print("  =  A[%2d:%-2d] B[%2d:%-2d]  %s" % (i1, i2, j1, j2, a[i1:i2].hex(" ")))
    else:
        print("  %-7s A[%2d:%-2d]=%-24s B[%2d:%-2d]=%s"
              % (tag, i1, i2, a[i1:i2].hex(" "), j1, j2, bb[j1:j2].hex(" ")))

print("\n=== 把 A 的差异段按 varint 拆开看看 ===")
for tag, i1, i2, j1, j2 in sm.get_opcodes():
    if tag == "equal":
        continue
    for name, seg in (("A", a[i1:i2]), ("B", bb[j1:j2])):
        if not seg:
            continue
        vals, i = [], 0
        while i < len(seg):
            v, k = state.varint_at(seg, i)
            if v is None or k == i:
                i += 1
                continue
            vals.append((i, k - i, v))
            i = k
        print("  %s %s -> varint 拆解 %s" % (name, seg.hex(" "), vals))
