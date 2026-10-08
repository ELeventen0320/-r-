# -*- coding: utf-8 -*-
"""抽取二进制中的 ASCII 字符串(含偏移), 便于定位 filepacket 加载逻辑附近的线索."""
import re
import sys

def strings(path, minlen=4):
    with open(path, "rb") as f:
        data = f.read()
    out = []
    cur = bytearray()
    start = 0
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
    path = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "grep"
    strs = strings(path)
    print("# %s: %d strings" % (path, len(strs)))

    if mode == "grep":
        kws = sys.argv[3:]
        for off, s in strs:
            low = s.lower()
            if any(k.lower() in low for k in kws):
                print("  @%-9d %s" % (off, s[:200]))
    elif mode == "range":
        lo, hi = int(sys.argv[3]), int(sys.argv[4])
        for off, s in strs:
            if lo <= off <= hi:
                print("  @%-9d %s" % (off, s[:250]))
    elif mode == "around":
        target = sys.argv[3]
        for idx, (off, s) in enumerate(strs):
            if target in s:
                print("### 命中 @%d : %s" % (off, s))
                for j in range(max(0, idx - 25), min(len(strs), idx + 25)):
                    print("   @%-9d %s" % (strs[j][0], strs[j][1][:200]))
                print()


if __name__ == "__main__":
    main()
