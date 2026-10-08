# -*- coding: utf-8 -*-
"""
严格 MessagePack 解码器: 逐字节解析, 报告消费比例与解码结果.
若某个负载的消费比例接近 100%, 基本可确认协议就是 MessagePack.
"""
import os
import struct
import sys

D = r"C:\Users\26912\Projects\wsgr-rt\capture\f10010"
FILES = ["10.0.2.15_S_C_53568.bin", "10.0.2.15_C_S_53568.bin",
         "10.0.2.15_S_C_40396.bin", "10.0.2.15_C_S_40396.bin"]


class Reader:
    def __init__(self, b):
        self.b = b
        self.i = 0

    def u8(self):
        v = self.b[self.i]; self.i += 1; return v

    def take(self, n):
        v = self.b[self.i:self.i + n]; self.i += n; return v


def parse(r, depth=0, budget=20000):
    """返回 python 对象; 失败抛异常."""
    if r.i >= len(r.b) or budget <= 0:
        raise ValueError("eof/budget")
    c = r.u8()
    if c <= 0x7F:
        return c
    if c >= 0xE0:
        return c - 256
    if 0x80 <= c <= 0x8F:
        n = c & 0x0F
        return {parse(r, depth + 1, budget - 1): parse(r, depth + 1, budget - 1) for _ in range(n)}
    if 0x90 <= c <= 0x9F:
        n = c & 0x0F
        return [parse(r, depth + 1, budget - 1) for _ in range(n)]
    if 0xA0 <= c <= 0xBF:
        n = c & 0x1F
        return r.take(n)
    if c == 0xC0:
        return None
    if c == 0xC2:
        return False
    if c == 0xC3:
        return True
    if c == 0xC4:
        return r.take(r.u8())
    if c == 0xC5:
        return r.take(struct.unpack(">H", r.take(2))[0])
    if c == 0xC6:
        return r.take(struct.unpack(">I", r.take(4))[0])
    if c == 0xCA:
        return struct.unpack(">f", r.take(4))[0]
    if c == 0xCB:
        return struct.unpack(">d", r.take(8))[0]
    if c == 0xCC:
        return r.u8()
    if c == 0xCD:
        return struct.unpack(">H", r.take(2))[0]
    if c == 0xCE:
        return struct.unpack(">I", r.take(4))[0]
    if c == 0xCF:
        return struct.unpack(">Q", r.take(8))[0]
    if c == 0xD0:
        return struct.unpack(">b", r.take(1))[0]
    if c == 0xD1:
        return struct.unpack(">h", r.take(2))[0]
    if c == 0xD2:
        return struct.unpack(">i", r.take(4))[0]
    if c == 0xD3:
        return struct.unpack(">q", r.take(8))[0]
    if c == 0xD9:
        return r.take(r.u8())
    if c == 0xDA:
        return r.take(struct.unpack(">H", r.take(2))[0])
    if c == 0xDB:
        return r.take(struct.unpack(">I", r.take(4))[0])
    if c == 0xDC:
        return [parse(r, depth + 1, budget - 1) for _ in range(struct.unpack(">H", r.take(2))[0])]
    if c == 0xDD:
        return [parse(r, depth + 1, budget - 1) for _ in range(struct.unpack(">I", r.take(4))[0])]
    if c == 0xDE:
        return {parse(r, depth + 1, budget - 1): parse(r, depth + 1, budget - 1)
                for _ in range(struct.unpack(">H", r.take(2))[0])}
    if c == 0xDF:
        return {parse(r, depth + 1, budget - 1): parse(r, depth + 1, budget - 1)
                for _ in range(struct.unpack(">I", r.take(4))[0])}
    raise ValueError("unsupported 0x%02x @%d" % (c, r.i - 1))


def main():
    for name in FILES:
        p = os.path.join(D, name)
        if not os.path.exists(p):
            continue
        b = open(p, "rb").read()
        r = Reader(b)
        print("=" * 90)
        print("### %s (%d 字节), 首 24 字节: %s" % (name, len(b), b[:24].hex(" ")))
        objs = []
        try:
            while r.i < len(b):
                objs.append(parse(r))
            print("  ✅ 全部解析成功! 共 %d 个顶层对象, 消费 %d/%d = %.1f%%" % (
                len(objs), r.i, len(b), 100 * r.i / len(b)))
            for o in objs[:6]:
                print("     -> %r" % (o if not isinstance(o, (bytes, bytearray)) else o[:80],))
        except Exception as ex:
            print("  ❌ 解析失败: %s   已消费 %d/%d = %.1f%%" % (
                ex, r.i, len(b), 100 * r.i / len(b)))
            print("     已解出的对象: %r" % (objs[:4],))


if __name__ == "__main__":
    main()
