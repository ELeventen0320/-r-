# -*- coding: utf-8 -*-
"""
★ 协议解码器 ★
已确认: lxnet 网络负载 = 明文 XOR 0xAE (单字节, 全局固定)
报文结构 (由 libtolua.so 的 lua_lxnet_messagepack_pushdata/getdata 反汇编得出):
    [0..6)   6 字节消息头
    [6..10)  uint32 LE 负载长度
    [10..)   负载 (MessagePack)
"""
import collections
import os
import struct
import sys

D = r"C:\Users\26912\Projects\wsgr-rt\capture\f10010"
KEY = 0xAE


def dec(b):
    return bytes(x ^ KEY for x in b)


def walk(buf, limit=40):
    """按 <6字节头><u32长度><负载> 切分消息."""
    msgs = []
    off = 0
    while off + 10 <= len(buf) and len(msgs) < limit:
        hdr = buf[off:off + 6]
        (ln,) = struct.unpack_from("<I", buf, off + 6)
        if ln < 0 or off + 10 + ln > len(buf):
            msgs.append(("BAD", off, hdr, ln, buf[off + 10:off + 10 + min(ln, 64)]))
            break
        msgs.append(("OK", off, hdr, ln, buf[off + 10:off + 10 + ln]))
        off += 10 + ln
    return msgs, off


def hexdump(b, n=192):
    out = []
    for i in range(0, min(len(b), n), 16):
        ch = b[i:i + 16]
        out.append("    %04x  %-47s  %s" % (i, " ".join("%02x" % c for c in ch),
                   "".join(chr(c) if 32 <= c < 127 else "." for c in ch)))
    if len(b) > n:
        out.append("    ... (%d 字节)" % len(b))
    return "\n".join(out)


def main():
    out = open(r"C:\Users\26912\Projects\wsgr-rt\capture\decoded.txt", "w", encoding="utf-8")

    def P(*a):
        print(*a)
        print(*a, file=out)

    files = sorted(os.listdir(D))
    for name in files:
        if not name.endswith(".bin"):
            continue
        b = open(os.path.join(D, name), "rb").read()
        plain = dec(b)
        P("=" * 100)
        P("### %s   (%d 字节, 已 XOR 0xAE)" % (name, len(b)))
        P(hexdump(plain, 256))
        msgs, used = walk(plain)
        P("  切分: %d 条消息, 消费 %d/%d 字节" % (len(msgs), used, len(plain)))
        for kind, off, hdr, ln, body in msgs[:12]:
            P("   [%s] off=%-6d hdr=%s len=%-6d body[:64]=%s" % (
                kind, off, hdr.hex(" "), ln,
                "".join(chr(c) if 32 <= c < 127 else "." for c in body[:64])))
        P("")
    out.close()
    print("\n-> %s" % r"C:\Users\26912\Projects\wsgr-rt\capture\decoded.txt")


if __name__ == "__main__":
    main()
