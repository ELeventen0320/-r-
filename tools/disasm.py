# -*- coding: utf-8 -*-
"""
ARM64 ELF 反汇编与调用图追踪 (基于 capstone).
用于从 libtolua.so 的 lxnet::Socketer::SendData 追出加密例程.

用法:
    python disasm.py <so> func <vaddr_hex> [指令数]
    python disasm.py <so> callgraph <vaddr_hex> [深度]
    python disasm.py <so> findcrypto [最小函数大小]
"""
import collections
import struct
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

KEYWORDS = ("Crypto", "Encrypt", "Decrypt", "Cipher", "Aes", "AES", "Rc4",
            "RC4", "Xor", "xor", "TEA", "xxtea", "XXTEA", "Md5", "MD5",
            "Base64", "Compress", "unzip", "zlib", "Deflate")


class ELF:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.d = f.read()
        assert self.d[:4] == b"\x7fELF", "not ELF"
        self.is64 = self.d[4] == 2
        e = "<"
        (self.e_type, self.e_machine, _e_ver, self.e_entry, self.e_phoff, self.e_shoff,
         self.e_flags, _e_ehsize, self.e_phentsize, self.e_phnum, self.e_shentsize,
         self.e_shnum, self.e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", self.d, 16)
        self.segs = []      # (vaddr, filesz, memsz, offset, flags)
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
                struct.unpack_from(e + "IIQQQQQQ", self.d, off)
            if p_type == 1:  # PT_LOAD
                self.segs.append((p_vaddr, p_filesz, p_memsz, p_offset, p_flags))
        # 节表 (取名字用)
        self.secs = []
        if self.e_shoff:
            shstr = None
            raw = []
            for i in range(self.e_shnum):
                off = self.e_shoff + i * self.e_shentsize
                raw.append(struct.unpack_from(e + "IIQQQQIIQQ", self.d, off))
            shstr = raw[self.e_shstrndx][4]
            for s in raw:
                name_off = s[0]
                end = self.d.index(b"\0", shstr + name_off)
                nm = self.d[shstr + name_off:end].decode("latin-1")
                self.secs.append({"name": nm, "addr": s[3], "off": s[4], "size": s[5],
                                  "flags": s[2]})

    def v2o(self, vaddr):
        for v, fsz, msz, off, fl in self.segs:
            if v <= vaddr < v + max(fsz, msz):
                return off + (vaddr - v)
        return None

    def read(self, vaddr, n):
        o = self.v2o(vaddr)
        if o is None:
            return None
        return self.d[o:o + n]

    def u32(self, vaddr):
        b = self.read(vaddr, 4)
        return struct.unpack("<I", b)[0] if b and len(b) == 4 else None

    def sec_of(self, vaddr):
        for s in self.secs:
            if s["addr"] and s["addr"] <= vaddr < s["addr"] + s["size"]:
                return s
        return None

    def exec_ranges(self):
        return [(v, v + max(f, m)) for v, f, m, o, fl in self.segs if fl & 1]


def make_md():
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


def bl_targets(md, elf, addr, count):
    """反汇编 count 条指令, 返回 (指令列表, 被调用地址集合)."""
    code = elf.read(addr, count * 4)
    if not code:
        return [], set()
    insns = list(md.disasm(code, addr))
    calls = set()
    for ins in insns:
        if ins.mnemonic in ("bl", "b") and ins.op_str.startswith("#"):
            try:
                calls.add(int(ins.op_str[1:], 16))
            except ValueError:
                pass
        elif ins.mnemonic in ("blr", "br"):
            pass
    return insns, calls


def in_exec(elf, a):
    return any(lo <= a < hi for lo, hi in elf.exec_ranges())


def cmd_func(elf, md, addr, n=400):
    insns, calls = bl_targets(md, elf, addr, n)
    sec = elf.sec_of(addr)
    print("### 函数 @0x%x   (节: %s)" % (addr, sec["name"] if sec else "?"))
    for ins in insns:
        mark = "  <-- CALL" if ins.mnemonic == "bl" else ""
        print("  %08x  %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
    print("\n### 调用的子函数: %s" % ", ".join("0x%x" % c for c in sorted(calls)))


def cmd_callgraph(elf, md, root, depth=2, maxfuncs=60):
    seen = set()
    order = []

    def walk(a, d, path):
        if d < 0 or len(seen) >= maxfuncs or a in seen or not in_exec(elf, a):
            return
        seen.add(a)
        order.append((a, d, path))
        insns, calls = bl_targets(md, elf, a, 3000)
        for c in sorted(calls):
            walk(c, d - 1, path + [a])

    walk(root, depth, [])
    for a, d, path in order:
        sec = elf.sec_of(a)
        insns, calls = bl_targets(md, elf, a, 3000)
        sym = ""
        print("%s0x%08x  d=%d  %-14s  insns=%d callees=%d" % (
            "  " * (depth - d), a, d, sec["name"] if sec else "?", len(insns), len(calls)))


def cmd_findcrypto(elf, md, minsize=16):
    """扫描 .dynsym 里带加密/压缩关键词的导出函数, 打印入口处若干指令."""
    print("### 导出符号中与加密/压缩相关的函数")
    hits = []
    for s in elf.secs:
        if s["name"] != ".dynsym":
            continue
    # 直接从 .dynstr 解析 (简化: 扫描 dynsym)
    for s in elf.secs:
        if s["name"] not in (".dynsym",):
            continue
        n = s["size"] // 24
        # 需要 .dynstr 偏移, 由 e_shstrndx 找不到; 简化: 用 link
    print("  (用 symbol 扫描模式见 elf_syms.py; 此处只做代码特征扫描)")
    # 代码特征: 找包含大量 eor (XOR) 指令的小函数
    for lo, hi in elf.exec_ranges():
        a = lo
        while a < hi:
            n = 0
            xors = 0
            while n < 64:
                w = elf.u32(a + n * 4)
                if w is None:
                    break
                if (w & 0xFF200000) == 0x4A000000:   # eor 指令族近似
                    xors += 1
                n += 1
            if xors >= 8:
                print("  0x%08x 附近 64 条指令里有 %d 条 EOR (疑似 XOR 循环)" % (a, xors))
            a += 0x40


if __name__ == "__main__":
    path = sys.argv[1]
    cmd = sys.argv[2]
    elf = ELF(path)
    md = make_md()
    print("# %s  machine=%d  segs=%d  entry=0x%x" % (path, elf.e_machine, len(elf.segs), elf.e_entry))
    for v, f, m, o, fl in elf.segs:
        print("#   LOAD v=0x%08x filesz=0x%x memsz=0x%x off=0x%x flags=%d%s" % (
            v, f, m, o, fl, "  EXEC" if fl & 1 else ""))
    if cmd == "func":
        cmd_func(elf, md, int(sys.argv[3], 16), int(sys.argv[4]) if len(sys.argv) > 4 else 400)
    elif cmd == "callgraph":
        cmd_callgraph(elf, md, int(sys.argv[3], 16), int(sys.argv[4]) if len(sys.argv) > 4 else 2)
    elif cmd == "findcrypto":
        cmd_findcrypto(elf, md)
