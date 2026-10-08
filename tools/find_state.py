# -*- coding: utf-8 -*-
"""
在服务端初始推送里定位"远征状态"数据.
思路: 已确认的动作帧里 远征ID 10001 以 varint 形式出现 (91 4e),
      若状态里记录了远征, 就能搜到同样的模式.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wsgr_proto import decrypt, parse_frames

CAP = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "capture"))
FILES = [
    os.path.join(CAP, "f3", "10.0.2.15_C_S_58340.bin"),
    os.path.join(CAP, "f10010", "10.0.2.15_C_S_53568.bin"),
]
# 已知的远征 ID (varint 编码)
PATTERNS = {
    "10001 (91 4e)": bytes.fromhex("91 4e"),
    "field5=10001 (28 91 4e)": bytes.fromhex("28 91 4e"),
}


def main():
    for path in FILES:
        if not os.path.exists(path):
            continue
        plain = decrypt(open(path, "rb").read())
        fr, used, sk = parse_frames(plain, 8)
        print("=" * 92)
        print("### %s  %d 字节 -> %d 帧" % (os.path.basename(path), len(plain), len(fr)))
        for off, ln, c in fr:
            mid = struct.unpack_from("<H", c, 0)[0] if len(c) >= 2 else -1
            print("   off=%-7d len=%-6d msgid=%-6d" % (off, ln, mid))
        print()
        for name, pat in PATTERNS.items():
            print("--- 搜索 %s ---" % name)
            start = 0
            hits = 0
            while hits < 12:
                i = plain.find(pat, start)
                if i < 0:
                    break
                s, e = max(0, i - 24), min(len(plain), i + 24)
                ctx = plain[s:e]
                # 找到所在帧
                owner = None
                for off, ln, c in fr:
                    if off <= i < off + ln:
                        owner = (off, ln, struct.unpack_from("<H", c, 0)[0])
                        break
                print("   @%-7d 帧=%s  %s" % (i, owner, ctx.hex(" ")))
                hits += 1
                start = i + 1
            if hits == 0:
                print("   (无)")
        print()


if __name__ == "__main__":
    main()
