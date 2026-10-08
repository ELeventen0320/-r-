# -*- coding: utf-8 -*-
"""极简 ELF .dynsym 导出符号列举器 (用于确认能否按名字 hook)."""
import struct
import sys


def parse_elf(path, keywords):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF":
        print("not ELF")
        return
    is64 = data[4] == 2
    little = data[5] == 1
    e = "<" if little else ">"
    if is64:
        e_shoff, = struct.unpack_from(e + "Q", data, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(e + "HHH", data, 0x3A)
        sh_fmt = e + "IIQQQQIIQQ"
    else:
        e_shoff, = struct.unpack_from(e + "I", data, 0x20)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(e + "HHH", data, 0x2E)
        sh_fmt = e + "IIIIIIIIII"
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        secs.append(struct.unpack_from(sh_fmt, data, off))

    def get(sec):
        return sec[4], sec[5], sec[6]  # offset, size, link

    shstr_off = secs[e_shstrndx][4]
    names = {}
    for i, s in enumerate(secs):
        no = s[0]
        end = data.index(b"\0", shstr_off + no)
        names[data[shstr_off + no:end].decode()] = i
    print("# %s  sections=%d" % (path, e_shnum))
    print("# 关键节: %s" % [n for n in names if n in (".dynsym", ".symtab", ".dynstr", ".strtab")])

    for symname, strname in ((".dynsym", ".dynstr"), (".symtab", ".strtab")):
        if symname not in names:
            continue
        sy = secs[names[symname]]
        st = secs[names[strname]]
        sy_off, sy_size = sy[4], sy[5]
        st_off = st[4]
        entsize = 24 if is64 else 16
        cnt = sy_size // entsize
        hits = []
        for i in range(cnt):
            off = sy_off + i * entsize
            if is64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(e + "IBBHQQ", data, off)
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(e + "IIIBBH", data, off)
            if st_name == 0 or st_value == 0:
                continue
            end = data.index(b"\0", st_off + st_name)
            nm = data[st_off + st_name:end].decode("latin-1")
            low = nm.lower()
            if any(k.lower() in low for k in keywords):
                hits.append((st_value, nm))
        print("### %s: %d 个匹配" % (symname, len(hits)))
        for v, nm in hits[:60]:
            print("    0x%08x  %s" % (v, nm))


if __name__ == "__main__":
    parse_elf(sys.argv[1], sys.argv[2:])
