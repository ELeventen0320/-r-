# -*- coding: utf-8 -*-
"""逐关键词统计二进制文件中的命中(不提前退出), 输出样本上下文."""
import os
import sys

KW = [
    "moefantasy", "jianniang", "checkVer", "getInitConfigs", "hmLogin",
    "loginServer", "hmLoginServer", "ade2688f", "HMS ", "passport",
    "initGame", "1.0/get/", "serverList", "access_token", "app_server_type",
    "getInitConfigs", "resUrl", "kr.moefantasy", "zjsnr", "zhanjian",
    "api/", "sdk", "udid", "client_version", "channel=", "market=",
]


def samples(data, pat, n=4, ctx=110):
    out = []
    start = 0
    total = 0
    while True:
        i = data.find(pat, start)
        if i < 0:
            break
        total += 1
        if len(out) < n:
            s = max(0, i - ctx)
            e = min(len(data), i + len(pat) + ctx)
            out.append("".join(chr(c) if 32 <= c < 127 else "." for c in data[s:e]))
        start = i + 1
    return total, out


def main(paths, keywords):
    for path in paths:
        with open(path, "rb") as f:
            data = f.read()
        print("=" * 78)
        print("FILE: %s (%d bytes)" % (os.path.basename(path), len(data)))
        for kw in keywords:
            for variant, label in ((kw.encode("ascii"), "ascii"),
                                   (kw.encode("utf-16-le"), "utf16")):
                total, ex = samples(data, variant)
                if total:
                    print("\n  >>> [%s/%s] %d hits" % (kw, label, total))
                    for s in ex:
                        print("      %s" % s)


if __name__ == "__main__":
    main(sys.argv[2:], [sys.argv[1]])
