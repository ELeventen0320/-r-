# -*- coding: utf-8 -*-
"""
解码 73KB 初始游戏数据 (XOR 0xAE + 帧切分 + TLV 字段扫描), 验证协议端到端可用.
TLV 规则 (由明文推断): tag 字节 t -> field = t>>3, wiretype = t&7
  wiretype 2 = length-delimited (后跟 1 字节长度, 视字段形态也可能是变长)
"""
import os
import re
import struct
import sys

D = r"C:\Users\26912\Projects\wsgr-rt\capture\f10010"
KEY = 0xAE
OUT = r"C:\Users\26912\Projects\wsgr-rt\capture\decoded_full.txt"


def crypt(b):
    return bytes(x ^ KEY for x in b)


def frames(buf):
    out, off = [], 0
    while off + 10 <= len(buf):
        hdr = buf[off:off + 6]
        (ln,) = struct.unpack_from("<I", buf, off + 6)
        if ln > 0x200000:
            break
        end = off + 10 + ln
        if end > len(buf):
            out.append(("TRUNC", off, hdr, ln, buf[off + 10:]))
            break
        out.append(("OK", off, hdr, ln, buf[off + 10:end]))
        off = end
    return out, off


def scan_tlv(b, limit=60):
    """粗略扫描 length-delimited 字段."""
    res = []
    i = 0
    while i + 2 <= len(b) and len(res) < limit:
        t = b[i]
        wt = t & 7
        fld = t >> 3
        if wt == 2 and 1 <= fld <= 60:
            ln = b[i + 1]
            if 0 < ln <= 64 and i + 2 + ln <= len(b):
                data = b[i + 2:i + 2 + ln]
                pr = sum(1 for c in data if 32 <= c < 127) / ln
                if pr > 0.9:
                    res.append((i, fld, ln, data.decode("latin-1")))
                    i += 2 + ln
                    continue
        i += 1
    return res


def main():
    out = open(OUT, "w", encoding="utf-8")

    def P(*a):
        print(*a)
        print(*a, file=out)

    name = "10.0.2.15_C_S_53568.bin"
    plain = crypt(open(os.path.join(D, name), "rb").read())
    P("### %s  解密后 %d 字节" % (name, len(plain)))
    P("前 64 字节: %s" % plain[:64].hex(" "))
    fr, used = frames(plain)
    P("帧切分: %d 条, 消费 %d/%d" % (len(fr), used, len(plain)))
    for kind, off, hdr, ln, body in fr[:10]:
        P("  [%s] off=%-7d hdr=%s len=%-6d" % (kind, off, hdr.hex(" "), ln))

    # 全部可见字符串
    runs = re.findall(rb"[\x20-\x7e]{6,}", plain)
    P("\n### 可见字符串 %d 条, 前 80 条 ###" % len(runs))
    for r in runs[:80]:
        P("   %s" % r.decode("latin-1")[:150])

    # TLV 字段
    P("\n### TLV 字段扫描 (前 60) ###")
    for off, fld, ln, s in scan_tlv(plain):
        P("   @%-6d field=%-3d len=%-3d %s" % (off, fld, ln, s[:110]))

    out.close()
    print("\n-> %s" % OUT)


if __name__ == "__main__":
    main()
