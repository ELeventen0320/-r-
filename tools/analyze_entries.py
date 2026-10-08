# -*- coding: utf-8 -*-
"""分析 APK 条目表: 最大条目 + 目录分布."""
import collections
import re

SRC = r"C:\Users\26912\Projects\wsgr-rt\notes\apk_entries.txt"

rows = []
with open(SRC, encoding="utf-8") as f:
    for line in f:
        m = re.match(r"\s*(\d+)\s+(\d+)\s+(.*)$", line.rstrip("\n"))
        if m:
            rows.append((int(m.group(1)), int(m.group(2)), m.group(3)))

rows.sort(reverse=True)
print("### 最大的 30 个条目 (usize, csize, name) ###")
for u, c, n in rows[:30]:
    print("%13d %13d  %s" % (u, c, n))

print("\n### 目录分布(未压缩字节) ###")
d = collections.Counter()
for u, c, n in rows:
    parts = n.split("/")
    key = "/".join(parts[:2]) if len(parts) > 1 else parts[0]
    d[key] += u
for k, v in d.most_common(25):
    print("%14d  %s" % (v, k))

print("\n### 全部 .so / .dex / assets 顶层文件 ###")
for u, c, n in sorted(rows, key=lambda r: r[2]):
    if n.endswith(".so") or n.endswith(".dex") or re.match(r"^assets/[^/]+$", n):
        print("%13d %13d  %s" % (u, c, n))
