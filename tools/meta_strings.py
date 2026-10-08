# -*- coding: utf-8 -*-
"""从 IL2CPP global-metadata.dat 中抽取 ASCII 字符串, 用于查找 API 端点与密钥."""
import os
import re
import struct
import sys

SRC = r"C:\Users\26912\Projects\wsgr-rt\apk\global-metadata.dat"
OUT = r"C:\Users\26912\Projects\wsgr-rt\notes\metadata_strings.txt"

HEADER_FIELDS = [
    "sanity", "version",
    "stringLiteralOffset", "stringLiteralSize",
    "stringLiteralDataOffset", "stringLiteralDataSize",
    "stringOffset", "stringSize",
    "eventsOffset", "eventsSize",
    "propertiesOffset", "propertiesSize",
    "methodsOffset", "methodsSize",
    "parameterDefaultValuesOffset", "parameterDefaultValuesSize",
    "fieldDefaultValuesOffset", "fieldDefaultValuesSize",
    "fieldAndParameterDefaultValueDataOffset", "fieldAndParameterDefaultValueDataSize",
    "fieldMarshaledSizesOffset", "fieldMarshaledSizesSize",
    "parametersOffset", "parametersSize",
    "fieldsOffset", "fieldsSize",
    "genericParametersOffset", "genericParametersSize",
    "genericParameterConstraintsOffset", "genericParameterConstraintsSize",
    "genericContainersOffset", "genericContainersSize",
    "nestedTypesOffset", "nestedTypesSize",
    "interfacesOffset", "interfacesSize",
    "vtableMethodsOffset", "vtableMethodsSize",
    "interfaceOffsetsOffset", "interfaceOffsetsSize",
    "typeDefinitionsOffset", "typeDefinitionsSize",
    "imagesOffset", "imagesSize",
    "assembliesOffset", "assembliesSize",
]


def parse_header(data):
    n = min(len(HEADER_FIELDS), (len(data) - 8) // 4)
    return {HEADER_FIELDS[i]: struct.unpack_from("<i", data, 8 + i * 4)[0] for i in range(n)}


def ascii_runs(data, minlen=5):
    out = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode("ascii"))
    return out


def main():
    with open(SRC, "rb") as f:
        data = f.read()
    print("file size: %d" % len(data))

    hdr = parse_header(data)
    print("### header ###")
    print("  version              = %d" % hdr["version"])
    print("  stringLiteralData    = off %d, size %d" % (hdr["stringLiteralDataOffset"], hdr["stringLiteralDataSize"]))
    print("  string (metadata)    = off %d, size %d" % (hdr["stringOffset"], hdr["stringSize"]))

    # 1) C# string literals
    off = hdr["stringLiteralDataOffset"]
    size = hdr["stringLiteralDataSize"]
    lit = data[off:off + size]
    lits = ascii_runs(lit, 4)
    print("\n### string literals: %d runs ###" % len(lits))

    # 2) whole-file strings (fallback / catches native-side blobs)
    alls = ascii_runs(data, 5)
    print("### whole-file runs: %d ###" % len(alls))

    with open(OUT, "w", encoding="utf-8") as f:
        f.write("# ---- STRING LITERALS (%d) ----\n" % len(lits))
        for s in lits:
            f.write(s + "\n")
        f.write("\n# ---- ALL RUNS (%d) ----\n" % len(alls))
        for s in alls:
            f.write(s + "\n")
    print("written %s (%d bytes)" % (OUT, os.path.getsize(OUT)))

    # 3) 直接高亮关键词
    KEYWORDS = [
        "moefantasy", "jianniang", "checkVer", "getInitConfigs", "hmLogin",
        "passport", "ade2688f", "HMS ", "authKey", "access_token",
        "loginServer", "hmLoginServer", "resUrl", "channel", "market",
        "get/login", "get/userInfo", "initGame", "serverList",
    ]
    print("\n### keyword hits ###")
    seen = set()
    for s in lits:
        low = s.lower()
        for kw in KEYWORDS:
            if kw.lower() in low and (kw, s) not in seen:
                seen.add((kw, s))
                print("  [%-14s] %s" % (kw, s[:220]))
                break


if __name__ == "__main__":
    main()
