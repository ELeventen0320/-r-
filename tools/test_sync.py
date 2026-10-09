# -*- coding: utf-8 -*-
"""
实验: 登录块里 7007/7012 的取值是否影响"完整同步 vs 增量状态"

真机登录块 (pC.pcap):
    5003(seq1), 7007=2(seq2), 7012=3(seq3), 7018(seq4)
本脚本对 7007/7012 取不同值各登录一次, 记录服务端返回的总字节数,
用返回体量来判断是否拿到完整同步 (完整同步约 63KB, 增量约 0.2~10KB)。
"""
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wsgr import bootstrap, proto, session as sessmod

SELF = os.path.dirname(os.path.abspath(__file__))
CAP = os.path.abspath(os.path.join(SELF, "..", "capture"))
TEMPLATE = os.path.join(CAP, "login_template.bin")
TOKEN = open(os.path.join(SELF, "token.txt")).read().strip()

#: (7007 值, 7012 值) 组合
CASES = [(2, 3), (0, 0), (1, 1), (14, 14), (2, 14), (0, 3)]


def build_frames(v7007, v7012):
    raw = open(TEMPLATE, "rb").read()
    plain = proto.decrypt(raw)
    fr = proto.parse_frames(plain, 0)
    out = []
    for off, ln, content in fr:
        if ln == 6 and out:
            break
        c = content
        if ln > 100:
            c = sessmod.patch_login_token(c, TOKEN)
        elif ln == 10:
            mid = proto.msgid_of(c)
            # 重建: <u16 msgid><u32 值>
            v = v7007 if mid == 7007 else (v7012 if mid == 7012 else None)
            if v is not None:
                c = struct.pack("<HI", mid, v)
        out.append((ln, proto.encrypt(proto.build_frame(c))))
    return out


def trial(v7007, v7012, host, port):
    s = socket.socket()
    s.settimeout(2.0)
    s.connect((host, port))
    for ln, pkt in build_frames(v7007, v7012):
        s.sendall(pkt)
        time.sleep(0.25)
    total, frames, t0 = 0, [], time.time()
    s.settimeout(1.5)
    while time.time() - t0 < 18:
        try:
            c = s.recv(65536)
        except socket.timeout:
            continue
        except Exception:
            break
        if not c:
            break
        total += len(c)
        for off, ln, content in proto.parse_frames(proto.decrypt(c), 0):
            frames.append((proto.msgid_of(content), ln))
    s.close()
    big = [f for f in frames if f[1] > 1000]
    return total, len(frames), big


def main():
    info = bootstrap.auth(TOKEN)
    notice = bootstrap.get_notice()
    from wsgr import server as srvmod
    act = srvmod.active_server(info, notice)
    host, port = srvmod.game_endpoint(notice, act["id"])
    print("目标服: id=%s %s -> %s:%d" % (act["id"], act["name"], host, port))
    print()
    print("%-14s %-10s %-8s %s" % ("7007/7012", "总字节", "帧数", "大帧"))
    for v7, v12 in CASES:
        try:
            total, nf, big = trial(v7, v12, host, port)
            print("%-14s %-10d %-8d %s"
                  % ("%d/%d" % (v7, v12), total, nf,
                     ["%d(%d)" % (m, l) for m, l in big[:5]] or "无"))
        except Exception as e:
            print("%-14s 失败: %s" % ("%d/%d" % (v7, v12), e))
        time.sleep(3)


if __name__ == "__main__":
    main()
