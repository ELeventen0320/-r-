# -*- coding: utf-8 -*-
"""分析内存 dump: 定位 moefantasy 上下文, 并抽取有意义的字符串."""
import os
import re
import sys

D = r"C:\Users\26912\Projects\wsgr-rt\capture\reg512k_7e1b020a1000.bin"
OUT = r"C:\Users\26912\Projects\wsgr-rt\capture\reg512k_analysis.txt"


def runs(data, minlen=6):
    out, cur, start = [], bytearray(), 0
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append((start, cur.decode("ascii")))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append((start, cur.decode("ascii")))
    return out


def main():
    with open(D, "rb") as f:
        data = f.read()
    print("size = %d" % len(data))
    out = open(OUT, "w", encoding="utf-8")

    def P(*a):
        print(*a)
        print(*a, file=out)

    # 1) moefantasy 上下文
    P("=" * 90)
    P("### moefantasy 出现位置")
    idx = 0
    while True:
        i = data.find(b"moefantasy", idx)
        if i < 0:
            break
        s, e = max(0, i - 200), min(len(data), i + 300)
        P("--- @%d (0x%x) ---" % (i, i))
        P("HEX: %s" % data[s:e][:160].hex(" "))
        P("ASC: %s" % "".join(chr(c) if 32 <= c < 127 else "." for c in data[s:e]))
        P("")
        idx = i + 1

    # 2) 所有字符串, 过滤出有意义的
    rs = runs(data, 6)
    P("=" * 90)
    P("### 字符串总数: %d" % len(rs))
    KEY = re.compile(r"http|xr-|server|auth|lua|function|local |self\.|\.lua|script|"
                     r"encrypt|decrypt|socketer|packet|app_|channel|account|token|"
                     r"hm_|login|patch|notice|version", re.I)
    picked = [(o, s) for o, s in rs if KEY.search(s)]
    P("### 命中关键词的字符串: %d" % len(picked))
    for o, s in picked[:120]:
        P("  @%-8d %s" % (o, s[:180]))

    # 3) 最长的 25 条字符串
    P("=" * 90)
    P("### 最长字符串 Top25")
    for o, s in sorted(rs, key=lambda x: -len(x[1]))[:25]:
        P("  (%4d) @%-8d %s" % (len(s), o, s[:200]))
    out.close()


if __name__ == "__main__":
    main()
