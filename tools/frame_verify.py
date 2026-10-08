# -*- coding: utf-8 -*-
"""
★ 最终帧格式验证 ★
格式: <u32 LE 总长度 L (含自身 4 字节)> + (L-4) 字节内容
用法: python frame_verify.py <bin> [起始偏移]
"""
import os
import struct
import sys

KEY = 0xAE
FILES = [
    (r"C:\Users\26912\Projects\wsgr-rt\capture\f3\10.0.2.15_S_C_58340.bin", 0),
    (r"C:\Users\26912\Projects\wsgr-rt\capture\f3\10.0.2.15_C_S_58340.bin", 0),
    (r"C:\Users\26912\Projects\wsgr-rt\capture\f3\10.0.2.15_C_S_58340.bin", 8),
    (r"C:\Users\26912\Projects\wsgr-rt\capture\f10010\10.0.2.15_C_S_53568.bin", 8),
    (r"C:\Users\26912\Projects\wsgr-rt\capture\f10010\10.0.2.15_S_C_53568.bin", 0),
]


def crypt(b):
    return bytes(x ^ KEY for x in b)


def walk(buf, start, maxn=4000):
    msgs, off = [], start
    while off + 4 <= len(buf):
        (ln,) = struct.unpack_from("<I", buf, off)
        if ln < 4 or off + ln > len(buf):
            msgs.append(("BAD", off, ln, buf[off:off + 24]))
            break
        msgs.append(("OK", off, ln, buf[off + 4:off + ln]))
        off += ln
        if len(msgs) > maxn:
            break
    return msgs, off


def main():
    for path, start in FILES:
        if not os.path.exists(path):
            continue
        plain = crypt(open(path, "rb").read())
        msgs, used = walk(plain, start)
        ok = sum(1 for m in msgs if m[0] == "OK")
        print("=" * 92)
        print("### %s  起始 %d  共 %d 字节" % (os.path.basename(path), start, len(plain)))
        print("    帧 %d 条 (成功 %d), 消费 %d/%d = %.1f%%   精确切完=%s"
              % (len(msgs), ok, used - start, len(plain) - start,
                 100.0 * (used - start) / (len(plain) - start), used == len(plain)))
        for kind, off, ln, body in msgs[:14]:
            vis = "".join(chr(c) if 32 <= c < 127 else "." for c in body[:70])
            print("   [%s] off=%-7d len=%-6d %s" % (kind, off, ln, vis))


if __name__ == "__main__":
    main()
