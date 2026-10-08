# -*- coding: utf-8 -*-
"""带偏移的完整十六进制+ASCII dump (解密后), 便于手工对齐帧边界."""
import sys

KEY = 0xAE


def main():
    path = sys.argv[1]
    off0 = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 512
    b = bytes(x ^ KEY for x in open(path, "rb").read())
    print("### %s  解密后 %d 字节, 显示 [%d, %d)" % (path.split("\\")[-1], len(b), off0, off0 + n))
    for i in range(off0, min(len(b), off0 + n), 16):
        ch = b[i:i + 16]
        print("%06x  %-47s  %s" % (i, " ".join("%02x" % c for c in ch),
              "".join(chr(c) if 32 <= c < 127 else "." for c in ch)))


if __name__ == "__main__":
    main()
