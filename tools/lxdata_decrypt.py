# -*- coding: utf-8 -*-
"""
lxdata 容器解密试探:
 1) 确认 magic 是否明文 (决定加密从哪个偏移开始)
 2) 对载荷段尝试单字节 XOR 全空间, 用"长可打印串 / .lua 文件名 / Lua 关键字"打分
"""
import collections
import os
import re
import sys

FILES = {
    "script": r"C:\Users\26912\Projects\wsgr-rt\apk\script.script",
    "xbask": r"C:\Users\26912\Projects\wsgr-rt\capture\xbask.core",
}
OUT = r"C:\Users\26912\Projects\wsgr-rt\capture\lxdata_decrypt.txt"


def score(b):
    """打分: 长可打印串数量 + 关键词."""
    runs = re.findall(rb"[\x20-\x7e]{6,}", b[:200000])
    s = sum(min(len(r), 60) for r in runs) / 1000.0
    for kw in (b".lua", b"function", b"local ", b"return", b"end\n", b"self",
               b"require", b"msgpack", b"http", b"moefantasy"):
        if kw in b[:200000]:
            s += 8
    return s, len(runs)


def main():
    out = open(OUT, "w", encoding="utf-8")

    def P(*a):
        print(*a)
        print(*a, file=out)

    for name, path in FILES.items():
        if not os.path.exists(path):
            continue
        raw = open(path, "rb").read()
        P("=" * 90)
        P("### %s (%d 字节) 前 16 字节: %s" % (name, len(raw), raw[:16].hex(" ")))
        P("    明文片段: %s" % "".join(chr(c) if 32 <= c < 127 else "." for c in raw[:16]))

        for start in (0, 10, 12, 16):
            body = raw[start:start + 300000]
            best = []
            for k in range(1, 256):
                d = bytes(x ^ k for x in body)
                sc, nr = score(d)
                best.append((sc, k, nr))
            best.sort(reverse=True)
            P("  --- 从偏移 %d 开始试单字节 XOR ---" % start)
            for sc, k, nr in best[:5]:
                d = bytes(x ^ k for x in body)
                sample = "".join(chr(c) if 32 <= c < 127 else "." for c in d[:120])
                P("    key=0x%02x score=%.2f 长串=%d  %s" % (k, sc, nr, sample))
    out.close()
    print("\n-> %s" % OUT)


if __name__ == "__main__":
    main()
