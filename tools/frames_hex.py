# -*- coding: utf-8 -*-
"""逐帧十六进制转储 (解密后), 用于识别动作消息."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wsgr_proto import decrypt, parse_frames

for path in sys.argv[1:]:
    if not os.path.exists(path):
        continue
    raw = open(path, "rb").read()
    plain = decrypt(raw)
    start = 0
    try:
        import struct
        if struct.unpack_from("<I", plain, 0)[0] > len(plain):
            start = 8
    except Exception:
        pass
    fr, used, sk = parse_frames(plain, start)
    print("### %s  %d 字节 -> %d 帧 (填充 %d)" % (os.path.basename(path), len(raw), len(fr), sk))
    for off, ln, c in fr:
        hexs = c.hex(" ")
        asc = "".join(chr(x) if 32 <= x < 127 else "." for x in c)
        print("  off=%-5d len=%-5d %-58s %s" % (off, ln, hexs[:110], asc[:56]))
    print()
