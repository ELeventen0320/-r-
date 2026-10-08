# -*- coding: utf-8 -*-
"""
通用 protobuf 风格解码器 (支持 wiretype 0/1/2/3/4/5, 含已废弃的 group),
用于解析服务端初始推送里的结构化状态 (如远征记录).
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wsgr_proto import decrypt, parse_frames

CAP = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "capture"))


def rd_varint(b, i):
    v = 0
    shift = 0
    while i < len(b):
        c = b[i]
        i += 1
        v |= (c & 0x7F) << shift
        if not (c & 0x80):
            return v, i
        shift += 7
        if shift > 63:
            break
    raise ValueError("varint too long")


def decode(b, i=0, end=None, depth=0, out=None):
    """返回 (字段列表, 新位置). 字段 = (field, wiretype, value)"""
    if end is None:
        end = len(b)
    if out is None:
        out = []
    while i < end:
        try:
            tag, i = rd_varint(b, i)
        except Exception:
            break
        field = tag >> 3
        wt = tag & 7
        if wt == 0:
            v, i = rd_varint(b, i)
            out.append((field, 0, v))
        elif wt == 1:
            if i + 8 > end:
                break
            out.append((field, 1, struct.unpack_from("<d", b, i)[0]))
            i += 8
        elif wt == 2:
            ln, i = rd_varint(b, i)
            if i + ln > end:
                break
            out.append((field, 2, b[i:i + ln]))
            i += ln
        elif wt == 3:                       # start group
            sub, i = decode(b, i, end, depth + 1, [])
            out.append((field, 3, sub))
        elif wt == 4:                       # end group
            return out, i
        elif wt == 5:
            if i + 4 > end:
                break
            out.append((field, 5, struct.unpack_from("<f", b, i)[0]))
            i += 4
        else:
            break
    return out, i


def show(fields, indent=0, limit=40):
    pad = "  " * indent
    n = 0
    for f, wt, v in fields:
        if n >= limit:
            print(pad + "...")
            break
        n += 1
        if wt == 2:
            inner = None
            try:
                inner, used = decode(v, 0, len(v), indent + 1, [])
                if used != len(v) or not inner:
                    inner = None
            except Exception:
                inner = None
            if inner:
                print("%sf%-3d (len=%-4d) {" % (pad, f, len(v)))
                show(inner, indent + 1, limit)
                print(pad + "}")
            else:
                vis = "".join(chr(c) if 32 <= c < 127 else "." for c in v[:40])
                print("%sf%-3d str/bytes(len=%-4d) %s | %s" % (pad, f, len(v), v[:20].hex(" "), vis))
        elif wt == 3:
            print("%sf%-3d group {" % (pad, f))
            show(v, indent + 1, limit)
            print(pad + "}")
        else:
            print("%sf%-3d wt=%d = %s" % (pad, f, wt, v))


def main():
    want = sys.argv[1] if len(sys.argv) > 1 else "10.0.2.15_C_S_58340.bin"
    path = os.path.join(CAP, "f3", want)
    if not os.path.exists(path):
        path = os.path.join(CAP, "f10010", want)
    plain = decrypt(open(path, "rb").read())
    fr, used, sk = parse_frames(plain, 8)
    for off, ln, c in fr:
        mid = struct.unpack_from("<H", c, 0)[0]
        if ln < 1000:
            continue
        print("=" * 92)
        print("### off=%d len=%d msgid=%d" % (off, ln, mid))
        body = c[2:]
        fields, used2 = decode(body, 0, len(body), 0, [])
        print("  解出 %d 个顶层字段, 消费 %d/%d" % (len(fields), used2, len(body)))
        show(fields, 1, 24)
        print()


if __name__ == "__main__":
    main()
