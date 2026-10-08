# -*- coding: utf-8 -*-
"""
帧格式最终验证 (带重同步)
格式: <u32 LE 总长度 L(含自身)> + (L-4) 字节内容
服务端流中帧之间夹有 0xAE 填充 -> 长度非法时跳过填充再同步.
"""
import os
import struct
import sys

KEY = 0xAE
FILES = [
    (r"C:\Users\26912\Projects\wsgr-rt\capture\f3\10.0.2.15_C_S_58340.bin", 8),
    (r"C:\Users\26912\Projects\wsgr-rt\capture\f10010\10.0.2.15_C_S_53568.bin", 8),
    (r"C:\Users\26912\Projects\wsgr-rt\capture\f3\10.0.2.15_S_C_58340.bin", 0),
]


def crypt(b):
    return bytes(x ^ KEY for x in b)


def walk(buf, start, maxn=20000):
    msgs, off, skipped = [], start, 0
    while off + 4 <= len(buf):
        (ln,) = struct.unpack_from("<I", buf, off)
        if ln < 4 or off + ln > len(buf):
            # 重同步: 跳过 0xAE 填充
            j = off
            while j < len(buf) and buf[j] == 0xAE:
                j += 1
            if j > off:
                skipped += j - off
                off = j
                continue
            msgs.append(("BAD", off, ln, buf[off:off + 24]))
            break
        msgs.append(("OK", off, ln, buf[off + 4:off + ln]))
        off += ln
        if len(msgs) > maxn:
            break
    return msgs, off, skipped


def main():
    for path, start in FILES:
        if not os.path.exists(path):
            continue
        plain = crypt(open(path, "rb").read())
        msgs, used, skipped = walk(plain, start)
        ok = [m for m in msgs if m[0] == "OK"]
        print("=" * 92)
        print("### %s  起始 %d  共 %d 字节" % (os.path.basename(path), start, len(plain)))
        print("    成功帧 %d 条, 消费 %d/%d = %.1f%%, 跳过填充 %d 字节"
              % (len(ok), used - start, len(plain) - start,
                 100.0 * (used - start) / (len(plain) - start), skipped))
        for kind, off, ln, body in msgs[:20]:
            vis = "".join(chr(c) if 32 <= c < 127 else "." for c in body[:66])
            print("   [%s] off=%-7d len=%-6d %s" % (kind, off, ln, vis))
        if msgs and msgs[-1][0] == "BAD":
            print("   (尾部未能切分: 可能抓包丢失)")
        print()


if __name__ == "__main__":
    main()
