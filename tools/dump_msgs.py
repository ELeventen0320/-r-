# -*- coding: utf-8 -*-
"""
消息转储器: 解密(XOR 0xAE) -> 切帧 -> 逐条打印头部与 TLV 字段.
用法: python dump_msgs.py <bin> [起始偏移]
"""
import os
import re
import struct
import sys

KEY = 0xAE


def crypt(b):
    return bytes(x ^ KEY for x in b)


def walk(buf, start=0, maxn=200):
    msgs, off = [], start
    while off + 10 <= len(buf) and len(msgs) < maxn:
        hdr = buf[off:off + 6]
        (ln,) = struct.unpack_from("<I", buf, off + 6)
        if ln > 0x80000 or off + 10 + ln > len(buf):
            msgs.append(("BAD", off, hdr, ln, buf[off + 10:off + 10 + 48]))
            break
        msgs.append(("OK", off, hdr, ln, buf[off + 10:off + 10 + ln]))
        off += 10 + ln
    return msgs, off


def fields(body, limit=14):
    """按 tag=(field<<3)|wiretype 扫 length-delimited 字段."""
    out, i = [], 0
    while i + 2 <= len(body) and len(out) < limit:
        t = body[i]
        wt = t & 7
        fld = t >> 3
        if wt == 2 and 1 <= fld <= 127:
            ln = body[i + 1]
            if 0 < ln <= 80 and i + 2 + ln <= len(body):
                d = body[i + 2:i + 2 + ln]
                pr = sum(1 for c in d if 32 <= c < 127) / ln
                if pr > 0.85:
                    out.append("f%d=%s" % (fld, d.decode("latin-1")))
                    i += 2 + ln
                    continue
        i += 1
    return out


def main():
    path = sys.argv[1]
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    plain = crypt(open(path, "rb").read())
    print("### %s  解密后 %d 字节" % (os.path.basename(path), len(plain)))
    print("    前 24 字节: %s" % plain[:24].hex(" "))
    msgs, used = walk(plain, start)
    print("    帧: %d 条, 消费 %d/%d\n" % (len(msgs), used - start, len(plain) - start))
    for kind, off, hdr, ln, body in msgs:
        u32, u16 = struct.unpack_from("<I", hdr, 0)[0], struct.unpack_from("<H", hdr, 4)[0]
        u16a, u32b = struct.unpack_from("<H", hdr, 0)[0], struct.unpack_from("<I", hdr, 2)[0]
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in body[:56])
        print("[%s] off=%-7d hdr=%-17s len=%-6d u32=%-6d u16=%-5d | u16=%-6d u32=%-10d"
              % (kind, off, hdr.hex(" "), ln, u32, u16, u16a, u32b))
        print("        %s" % txt)
        fl = fields(body)
        if fl:
            print("        TLV: %s" % "  ".join(fl))
        print()


if __name__ == "__main__":
    main()
