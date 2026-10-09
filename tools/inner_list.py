# -*- coding: utf-8 -*-
"""列出某帧内层消息的完整清单 (按位置), 用于理解容器结构."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wsgr import proto
from inner_v2 import split_inner

CAP = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "capture"))
TARGET = os.path.join(CAP, "f10010", "10.0.2.15_C_S_53568.bin")

NAMES = {
    0x1BDB: "★远征状态",
    0x1BE0: "领取请求",
    0x1BE1: "领取回执",
    0x1BE2: "?",
    0x1BB3: "每日签到",
    0x1B09: "记录类A",
    0x1B0A: "记录类B",
    0x1B00: "?", 0x1B01: "?", 0x1B10: "?", 0x1B11: "?",
    0x1B14: "?", 0x1B15: "?", 0x1B16: "?", 0x1B17: "?",
    0x1B5C: "?", 0x1B5E: "?", 0x1B59: "?", 0x1B60: "?",
    0x1B6F: "?", 0x1B71: "?", 0x1B80: "?", 0x1B88: "?",
    0x1BB1: "?", 0x1BB8: "?", 0x1BBF: "?",
}


def main():
    plain = proto.decrypt(open(TARGET, "rb").read())
    for off, ln, content in proto.parse_frames(plain, 8):
        if off != 251:
            continue
        body = content[2:]
        msgs = split_inner(body)
        print("帧 off=251 len=%d  内层消息 %d 条" % (ln, len(msgs)))
        print("%-8s %-8s %-7s %-6s %s" % ("位置", "msgid", "hex", "长度", "备注"))
        for pos, mid, c in msgs:
            print("%-8d %-8d 0x%04x %-6d %s"
                  % (pos, mid, mid, len(c), NAMES.get(mid, "")))
        # 重点: 7131 周边
        print("\n=== 7131 (0x1bdb) 周边 500 字节 ===")
        for i, (pos, mid, c) in enumerate(msgs):
            if mid == 0x1BDB:
                print("  7131 位于第 %d 条, @%d, 内容 %d 字节" % (i, pos, len(c)))
                print("  前一条: msgid=%d @%d 长度=%d" % (msgs[i-1][1], msgs[i-1][0], len(msgs[i-1][2])) if i > 0 else "  (首条)")
                if i + 1 < len(msgs):
                    print("  后一条: msgid=%d @%d 长度=%d" % (msgs[i+1][1], msgs[i+1][0], len(msgs[i+1][2])))
                print("  内容 hex: %s" % c[:160].hex(" "))
                break
        else:
            print("  未找到 0x1bdb! 说明被切分规则漏掉")
            # 手动定位
            idx = body.find(bytes([0xDB, 0x1B]))
            print("  手动 find 0x1bdb @%d" % idx)
            if idx >= 0:
                for pos, mid, c in msgs:
                    if abs(pos - idx) < 400:
                        print("    附近: @%d msgid=%d len=%d" % (pos, mid, len(c)))
        break


if __name__ == "__main__":
    main()
