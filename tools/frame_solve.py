# -*- coding: utf-8 -*-
"""
穷举帧格式: 试遍 (头长, 长度字段偏移, 长度字段宽度), 用"能干净切完的字节数"打分.
"""
import os
import struct
import sys

KEY = 0xAE
FILES = [
    (r"C:\Users\26912\Projects\wsgr-rt\capture\f3\10.0.2.15_C_S_58340.bin", 8),
    (r"C:\Users\26912\Projects\wsgr-rt\capture\f10010\10.0.2.15_C_S_53568.bin", 8),
    (r"C:\Users\26912\Projects\wsgr-rt\capture\f10010\10.0.2.15_S_C_53568.bin", 0),
]


def crypt(b):
    return bytes(x ^ KEY for x in b)


def try_layout(buf, start, hdr, loff, lsz, known_ids):
    off = start
    n = 0
    while off + hdr + lsz <= len(buf):
        if lsz == 2:
            (ln,) = struct.unpack_from("<H", buf, off + loff)
        elif lsz == 4:
            (ln,) = struct.unpack_from("<I", buf, off + loff)
        elif lsz == 1:
            ln = buf[off + loff]
        else:
            return n, False
        if ln <= 0 or ln > 400000:
            return n, False
        step = hdr + lsz + ln
        if off + step > len(buf):
            return n, False
        if known_ids is not None:
            known_ids.add(buf[off:off + min(hdr, 6)].hex(" "))
        off += step
        n += 1
        if n > 5000:
            break
    return n, (off == len(buf))


def main():
    for path, start in FILES:
        if not os.path.exists(path):
            continue
        buf = crypt(open(path, "rb").read())
        print("=" * 88)
        print("### %s  (%d 字节), 从偏移 %d 开始" % (os.path.basename(path), len(buf), start))
        results = []
        for hdr in (2, 4, 6, 8, 10):
            for loff in range(2, hdr + 1):
                for lsz in (1, 2, 4):
                    if loff + lsz > hdr + 4:
                        continue
                    n, exact = try_layout(buf, start, hdr, loff, lsz, None)
                    results.append((n, exact, hdr, loff, lsz))
        results.sort(key=lambda r: (-r[0], -int(r[1])))
        for n, exact, hdr, loff, lsz in results[:8]:
            print("   hdr=%-2d lsz=%-2d len@%-2d  ->  %4d 帧   精确切完=%s"
                  % (hdr, lsz, loff, n, exact))
        # 用最优组合打印前 12 条的头部
        n, exact, hdr, loff, lsz = results[0]
        print("   >>> 最优组合 hdr=%d len@%d len=%d 的前 12 帧头:" % (hdr, loff, lsz))
        off = start
        for i in range(12):
            if off + hdr + lsz > len(buf):
                break
            if lsz == 2:
                (ln,) = struct.unpack_from("<H", buf, off + loff)
            elif lsz == 4:
                (ln,) = struct.unpack_from("<I", buf, off + loff)
            else:
                ln = buf[off + loff]
            print("     #%-2d off=%-7d hdr=%-20s len=%-6d" % (
                i, off, buf[off:off + hdr].hex(" "), ln))
            if ln <= 0 or ln > 400000:
                break
            off += hdr + lsz + ln


if __name__ == "__main__":
    main()
