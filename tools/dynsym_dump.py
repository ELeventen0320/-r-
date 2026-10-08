# -*- coding: utf-8 -*-
"""完整转储 .dynsym 并按关键词过滤 (不跳过 st_value==0 的项)."""
import struct
import sys


def main(path, kws):
    with open(path, "rb") as f:
        d = f.read()
    e = "<"
    (_, _, _, _, _, e_shoff, _, _, _, _, e_shentsize, e_shnum, e_shstrndx) = \
        struct.unpack_from(e + "HHIQQQIHHHHHH", d, 16)
    secs = []
    for i in range(e_shnum):
        secs.append(struct.unpack_from(e + "IIQQQQIIQQ", d, e_shoff + i * e_shentsize))
    shstr = secs[e_shstrndx][4]
    names = {}
    for i, s in enumerate(secs):
        end = d.index(b"\0", shstr + s[0])
        names[d[shstr + s[0]:end].decode()] = i

    for secname in (".dynsym", ".symtab"):
        if secname not in names:
            continue
        sy = secs[names[secname]]
        strname = ".dynstr" if secname == ".dynsym" else ".strtab"
        if strname not in names:
            continue
        st = secs[names[strname]]
        sy_off, sy_size = sy[4], sy[5]
        st_off = st[4]
        cnt = sy_size // 24
        print("### %s  (%d 项)" % (secname, cnt))
        for i in range(cnt):
            off = sy_off + i * 24
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", d, off)
            if st_name == 0:
                continue
            end = d.index(b"\0", st_off + st_name)
            nm = d[st_off + st_name:end].decode("latin-1")
            low = nm.lower()
            if any(k.lower() in low for k in kws):
                kind = "FUNC" if (st_info & 0xF) == 2 else ("OBJ" if (st_info & 0xF) == 1 else "?")
                print("  0x%08x  size=%-6d %-4s  %s" % (st_value, st_size, kind, nm))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
