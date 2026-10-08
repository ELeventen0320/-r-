# -*- coding: utf-8 -*-
"""对协议负载暴力尝试常见简单变换, 判断是否只是轻量混淆."""
import os
import sys
import zlib

D = r"C:\Users\26912\Projects\wsgr-rt\capture\f10010"
FILES = ["10.0.2.15_C_S_53568.bin", "10.0.2.15_S_C_53568.bin", "10.0.2.15_C_S_40396.bin"]


def printable_ratio(b):
    return sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13)) / max(1, len(b))


def score(b):
    """打分: 可打印比例 + JSON/文本特征."""
    pr = printable_ratio(b)
    bonus = 0
    for tok in (b'{"', b'":"', b'":"', b'error', b'data', b'ship', b'user', b'[{"'):
        if tok in b:
            bonus += 0.5
    return pr + bonus


def nibble_swap(b):
    return bytes(((x & 0x0F) << 4) | (x >> 4) for x in b)


def bitrev(b):
    tbl = [int('{:08b}'.format(i)[::-1], 2) for i in range(256)]
    return bytes(tbl[x] for x in b)


def main():
    out = open(os.path.join(D, "transform_bruteforce.txt"), "w", encoding="utf-8")

    def P(*a):
        print(*a)
        print(*a, file=out)

    for name in FILES:
        p = os.path.join(D, name)
        if not os.path.exists(p):
            continue
        b = open(p, "rb").read()
        P("=" * 90)
        P("### %s (%d bytes) 原始可打印率=%.3f" % (name, len(b), printable_ratio(b)))

        results = []
        # 单字节 XOR
        for k in range(1, 256):
            results.append(("xor 0x%02x" % k, score(bytes(x ^ k for x in b[:20000]))))
        # 去高位 / 加高位
        results.append(("and 0x7f", score(bytes(x & 0x7F for x in b[:20000]))))
        results.append(("or 0x80", score(bytes(x | 0x80 for x in b[:20000]))))
        results.append(("not", score(bytes(x ^ 0xFF for x in b[:20000]))))
        results.append(("nibble swap", score(nibble_swap(b[:20000]))))
        results.append(("bitrev", score(bitrev(b[:20000]))))
        # 位偏移
        for sh in (1, 2, 3, 4):
            results.append(("rol %d" % sh, score(bytes(((x << sh) | (x >> (8 - sh))) & 0xFF for x in b[:20000]))))
            results.append(("ror %d" % sh, score(bytes(((x >> sh) | (x << (8 - sh))) & 0xFF for x in b[:20000]))))
        # 加/减常量
        for c in (1, 2, 0x80):
            results.append(("add %d" % c, score(bytes((x + c) & 0xFF for x in b[:20000]))))
            results.append(("sub %d" % c, score(bytes((x - c) & 0xFF for x in b[:20000]))))

        results.sort(key=lambda r: -r[1])
        P("  Top 8 变换:")
        for nm, sc in results[:8]:
            P("    %-16s score=%.3f" % (nm, sc))

        # 打印最优 xor 结果样本
        best = results[0][0]
        if best.startswith("xor"):
            k = int(best.split()[1], 16)
            dec = bytes(x ^ k for x in b[:400])
            P("  最佳 XOR(0x%02x) 前400字节: %s" % (k, dec.decode("latin-1").replace("\n", " ")[:300]))
    out.close()


if __name__ == "__main__":
    main()
