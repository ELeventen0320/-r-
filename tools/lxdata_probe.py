# -*- coding: utf-8 -*-
"""分析 lxdata 容器: 熵/结构/明文串/XOR 试探."""
import collections
import math
import sys

PATH = r"C:\Users\26912\Projects\wsgr-rt\apk\script.script"
KW = ["moefantasy", "jianniang", "checkVer", "hmLogin", "http", "login",
      "lua", "Lua", "function", "return", "local", "require", "main.lua"]


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def main():
    with open(PATH, "rb") as f:
        data = f.read()
    print("size=%d" % len(data))
    print("head 32: %s" % data[:32].hex(" "))
    print("entropy(head 1MB) = %.4f / 8.0" % entropy(data[:1 << 20]))
    print("entropy(last 1MB) = %.4f / 8.0" % entropy(data[-1 << 20:]))

    # 0 字节分布是否均匀 => 加密/压缩
    zero = data.count(0) / len(data)
    print("zero-byte ratio = %.4f" % zero)

    # 明文关键词
    print("\n### 关键词(原始) ###")
    for kw in KW:
        n = data.count(kw.encode())
        if n:
            print("  %-12s %d" % (kw, n))

    # ASCII 串统计
    runs = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= 6:
                runs.append(cur.decode())
            cur = bytearray()
    print("\n### ASCII 串 >=6: %d 条, 最长 15 条 ###" % len(runs))
    for s in sorted(runs, key=len, reverse=True)[:15]:
        print("  (%3d) %s" % (len(s), s[:160]))

    # 单字节 XOR 试探
    print("\n### 单字节 XOR 试探 (找 'function'/'moefantasy') ###")
    found = False
    for k in range(1, 256):
        d = bytes(b ^ k for b in data[:2 << 20])
        if b"function" in d or b"moefantasy" in d or b"local" in d:
            print("  key=0x%02x  hit" % k)
            found = True
    if not found:
        print("  无")

    # 首 4 字节可能是长度 -> 检查
    print("\n### 头部结构猜测 ###")
    import struct
    for off in (0, 4, 8, 10, 12, 16):
        for fmt, name in (("<I", "u32"), ("<H", "u16")):
            try:
                v = struct.unpack_from(fmt, data, off)[0]
                if 0 < v <= len(data):
                    print("  off=%2d %s = %d (file*%.3f)" % (off, name, v, v / len(data)))
            except Exception:
                pass


if __name__ == "__main__":
    main()
