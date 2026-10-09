# -*- coding: utf-8 -*-
"""
内层字段编码 —— 双样本差分分析

原理:
  两份抓包是同一账号、相近时间(相差约30分钟)、不同会话。
  因此:
    - 内容**完全相同**的内层消息 = 静态数据 (配置/表数据)
    - 内容**不同**的内层消息 = 会话状态, 差异位置即字段边界
  对同一 msgid 取两份样本做逐字节对齐(difflib), 差异区间就是变长字段所在.

输出:
  每个 msgid 的两份样本长度、是否相同、差异区间、差异前后的公共上下文.
"""
import difflib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wsgr import proto, state

CAP = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "capture"))

SOURCES = [("A=f10010", "f10010", "10.0.2.15_C_S_53568.bin"),
           ("B=f3", "f3", "10.0.2.15_C_S_58340.bin")]

NAMES = {0x1BDB: "★远征状态", 0x1BB3: "每日签到", 0x1BE1: "领取回执",
         0x1BE2: "7138", 0x1B62: "服务器时间", 0x1B5E: "7006", 0x1B5C: "7004",
         0x1B60: "7008", 0x1B88: "7048", 0x1B20: "6944", 0x1B01: "6913",
         0x1B6F: "7023", 0x1B96: "7062", 0x1B32: "6962", 0x1B40: "6976",
         0x1B97: "7063", 0x1BAA: "7082", 0x1BAB: "7083", 0x1BFF: "7167",
         0x1B00: "6912", 0x1BB8: "7096", 0x1B07: "6919", 0x1BF6: "7158",
         0x1B06: "6918", 0x1B09: "6921"}


def collect(label, sub, name):
    path = os.path.join(CAP, sub, name)
    plain = proto.decrypt(open(path, "rb").read())
    msgs = {}
    for off, ln, content in proto.parse_frames(plain, 8):
        if ln < 1000:
            continue
        for pos, mid, c in state.split_inner(content[2:]):
            msgs.setdefault(mid, []).append(c)
    return msgs


def hexdump_line(b):
    return b.hex(" ") if len(b) <= 24 else (b[:12].hex(" ") + " ... " + b[-8:].hex(" "))


def main():
    data = {label: collect(label, sub, name) for label, sub, name in SOURCES}
    labels = list(data.keys())
    A, B = data[labels[0]], data[labels[1]]

    common = sorted(set(A) & set(B))
    onlyA = sorted(set(A) - set(B))
    onlyB = sorted(set(B) - set(A))

    print("=" * 86)
    print("A = %s   B = %s" % (labels[0], labels[1]))
    print("公共 msgid: %d  仅A: %d  仅B: %d" % (len(common), len(onlyA), len(onlyB)))
    print("仅A: %s" % [hex(m) for m in onlyA[:14]])
    print("仅B: %s" % [hex(m) for m in onlyB[:14]])

    ident, diff = [], []
    for mid in common:
        ca, cb = A[mid][0], B[mid][0]
        (ident if ca == cb else diff).append(mid)

    print("\n内容完全相同 (静态): %d 个 -> %s"
          % (len(ident), [hex(m) for m in ident[:16]]))
    print("内容有差异 (状态): %d 个 -> %s"
          % (len(diff), [hex(m) for m in diff[:16]]))

    print("\n" + "=" * 86)
    print("### 有差异的消息逐条对齐")
    for mid in diff:
        ca, cb = A[mid][0], B[mid][0]
        nm = NAMES.get(mid, "")
        print("\n--- msgid=%d (0x%04x) %s : A=%d 字节  B=%d 字节"
              % (mid, mid, nm, len(ca), len(cb)))
        sm = difflib.SequenceMatcher(a=ca, b=cb, autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                if i2 - i1 >= 3:
                    print("    = A[%d:%d] %s" % (i1, i2, hexdump_line(ca[i1:i2])))
                continue
            print("    %-8s A[%d:%d]=%-26s | B[%d:%d]=%s"
                  % (tag, i1, i2, ca[i1:i2].hex(" "), j1, j2, cb[j1:j2].hex(" ")))

    print("\n" + "=" * 86)
    print("### 重点: 远征状态 7131 的字段切分尝试")
    for label, D in ((labels[0], A), (labels[1], B)):
        if 0x1BDB not in D:
            continue
        c = D[0x1BDB][0]
        print("\n  %s  内容 %d 字节:" % (label, len(c)))
        print("    %s" % c.hex(" "))
        # 尝试: 逐字节标出合法 tag 位置
        pos = []
        i = 0
        while i < len(c):
            tag = c[i]
            f, wt = tag >> 3, tag & 7
            if f != 0 and f < 200 and wt in (0, 1, 2, 5):
                pos.append((i, f, wt))
            i += 1
        print("    可能的 tag 位置: %s" % [(p, "f%d/w%d" % (f, w)) for p, f, w in pos[:18]])


if __name__ == "__main__":
    main()
