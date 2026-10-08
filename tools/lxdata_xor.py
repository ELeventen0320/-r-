# -*- coding: utf-8 -*-
"""
判定 lxdata 容器是否使用"固定密钥流(无每文件 IV)"加密:
  若两文件同偏移 XOR 后出现长零串 => 那些位置两边明文都是 0 => 密钥流固定
同时输出最长零串处的密文片段 (那正是密钥流本身).
"""
import collections
import math
import os
import sys

FILES = {
    "xbask": r"C:\Users\26912\Projects\wsgr-rt\capture\xbask.core",
    "xbask32": r"C:\Users\26912\Projects\wsgr-rt\capture\32bits.xbask.core",
    "script": r"C:\Users\26912\Projects\wsgr-rt\apk\script.script",
}
OUT = r"C:\Users\26912\Projects\wsgr-rt\capture\lxdata_xor.txt"


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def longest_zero_run(b):
    best = cur = 0
    best_at = 0
    for i, x in enumerate(b):
        if x == 0:
            cur += 1
            if cur > best:
                best, best_at = cur, i - cur + 1
        else:
            cur = 0
    return best, best_at


def main():
    data = {}
    for k, p in FILES.items():
        if os.path.exists(p):
            with open(p, "rb") as f:
                data[k] = f.read()
            print("%-8s %d bytes  head=%s" % (k, len(data[k]), data[k][:16].hex(" ")))
        else:
            print("%-8s MISSING" % k)

    out = open(OUT, "w", encoding="utf-8")

    def P(*a):
        print(*a)
        print(*a, file=out)

    keys = list(data)
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            a, b = data[keys[i]], data[keys[j]]
            n = min(len(a), len(b))
            x = bytes(p ^ q for p, q in zip(a[:n], b[:n]))
            z = x.count(0)
            run, at = longest_zero_run(x)
            P("=" * 88)
            P("%s XOR %s   (n=%d)" % (keys[i], keys[j], n))
            P("  熵=%.4f   零字节=%d (%.3f%%)   最长零串=%d @%d" % (
                entropy(x), z, 100 * z / n, run, at))
            # 展示最长零串附近: 两文件在此处都是纯密钥流
            if run >= 32:
                s = max(0, at - 16)
                e = min(n, at + min(run + 16, 160))
                P("  --- 最长零串附近 (密钥流可见) ---")
                P("  %s[%d:%d] = %s" % (keys[i], s, e, a[s:e].hex(" ")))
                P("  %s[%d:%d] = %s" % (keys[j], s, e, b[s:e].hex(" ")))
            # 零串长度直方图
            runs = []
            cur = 0
            for v in x:
                if v == 0:
                    cur += 1
                else:
                    if cur:
                        runs.append(cur)
                    cur = 0
            if cur:
                runs.append(cur)
            if runs:
                runs.sort(reverse=True)
                P("  最长 12 段零串: %s" % runs[:12])
    out.close()
    print("\n-> %s" % OUT)


if __name__ == "__main__":
    main()
