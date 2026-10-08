# -*- coding: utf-8 -*-
"""在内存 dump 中定位关键词并输出上下文 (含二进制周边, 便于识别 Lua 字节码/源码)."""
import os
import re
import sys

FILES = [
    r"C:\Users\26912\Projects\wsgr-rt\capture\mem1.bin",
    r"C:\Users\26912\Projects\wsgr-rt\capture\mem2.bin",
]
KW = ["app_version", "patch_list", "xr_cn_release", "hm_sdk_android",
      "server_list", "account_pi", "xr-server", "moefantasy",
      "SetEncryptKey", "encrypt", "decrypt", "socketer", "hmLogin", "auth"]

OUT = r"C:\Users\26912\Projects\wsgr-rt\capture\mem_strings.txt"


def main():
    with open(OUT, "w", encoding="utf-8") as out:
        for path in FILES:
            if not os.path.exists(path):
                continue
            with open(path, "rb") as f:
                data = f.read()
            print("=" * 90)
            print("FILE %s (%d bytes)" % (os.path.basename(path), len(data)))
            out.write("=" * 90 + "\nFILE %s (%d bytes)\n" % (os.path.basename(path), len(data)))
            for kw in KW:
                pb = kw.encode()
                idxs = []
                start = 0
                while True:
                    i = data.find(pb, start)
                    if i < 0 or len(idxs) >= 6:
                        break
                    idxs.append(i)
                    start = i + 1
                if not idxs:
                    continue
                print("  [%s] %d 处, 首现 @%d" % (kw, len(idxs), idxs[0]))
                out.write("\n### [%s] @%s\n" % (kw, idxs))
                for i in idxs[:2]:
                    s = max(0, i - 300)
                    e = min(len(data), i + 900)
                    blob = data[s:e]
                    out.write("--- ctx @%d ---\n" % i)
                    out.write("HEX: %s\n" % blob[:120].hex(" "))
                    out.write("ASC: %s\n" % "".join(chr(c) if 32 <= c < 127 else "." for c in blob[:900]))
                    out.write("\n")
    print("written %s" % OUT)


if __name__ == "__main__":
    main()
