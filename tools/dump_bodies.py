# -*- coding: utf-8 -*-
"""解压并完整打印抓到的响应正文."""
import glob
import json
import os
import sys
import zlib

d = r"C:\Users\26912\Projects\wsgr-rt\capture\bodies"
out = open(r"C:\Users\26912\Projects\wsgr-rt\capture\bodies_full.txt", "w", encoding="utf-8")


def dump(name, data):
    out.write("=" * 100 + "\n")
    out.write("### %s  (%d bytes)\n" % (name, len(data)))
    try:
        dec = zlib.decompress(data)
        out.write("[zlib -> %d bytes]\n" % len(dec))
    except Exception:
        dec = data
    txt = dec.decode("utf-8", "replace")
    # 美化 JSON
    try:
        obj = json.loads(txt)
        txt = json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        pass
    out.write(txt + "\n")


for p in sorted(glob.glob(os.path.join(d, "*.bin"))):
    with open(p, "rb") as f:
        dump(os.path.basename(p), f.read())

out.close()
print("written, size=%d" % os.path.getsize(r"C:\Users\26912\Projects\wsgr-rt\capture\bodies_full.txt"))
