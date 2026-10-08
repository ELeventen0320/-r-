# -*- coding: utf-8 -*-
"""
在 lxdata 文件头部(表头/目录区, 明文很可能大片为 0)探测密钥流周期.
若 C = P xor KS 且 KS 短周期, 则密文在此区的重合指数会在该周期处突增.
"""
import os
import sys

FILES = {
    "script": r"C:\Users\26912\Projects\wsgr-rt\apk\script.script",
    "xbask": r"C:\Users\26912\Projects\wsgr-rt\capture\xbask.core",
}
HEAD = 8192


def coincidence(b, p):
    if len(b) <= p:
        return 0.0
    same = sum(1 for i in range(len(b) - p) if b[i] == b[i + p])
    return same / (len(b) - p)


def main():
    for name, path in FILES.items():
        if not os.path.exists(path):
            print("%s missing" % name)
            continue
        with open(path, "rb") as f:
            h = f.read(HEAD)
        print("=" * 80)
        print("%s  前 %d 字节   entropy=%.4f" % (name, len(h),
              -sum((h.count(x) / len(h)) * __import__("math").log2(h.count(x) / len(h))
                   for x in set(h))))
        # 跳过 10 字节明文头
        body = h[10:]
        vals = sorted(((coincidence(body, p), p) for p in range(1, 129)), reverse=True)
        print("  重合指数 Top10 (p: 值):  %s" % ", ".join("p%d:%.4f" % (p, v) for v, p in vals[:10]))
        print("  随机基准 ≈ %.4f" % (1 / 256))
        print("  首个 64 字节: %s" % h[:64].hex(" "))
        # 检测头部是否存在连续同值段
        runs = []
        cur = 1
        for i in range(1, len(body)):
            if body[i] == body[i - 1]:
                cur += 1
            else:
                if cur >= 4:
                    runs.append((cur, i - cur))
                cur = 1
        print("  连续同值段(>=4): %s" % runs[:10])


if __name__ == "__main__":
    main()
