# -*- coding: utf-8 -*-
"""
★ 战舰少女R 脱机客户端原型 ★
协议要点 (已全部实测确认):
  加密 : 明文 XOR 0xAE  (单字节, 全局固定)
  帧   : [0..6) 消息头(6B) | [6..10) u32LE 负载长度 | [10..) 负载
用法 :
  python wsgr_client.py replay   # 重放抓到的请求并解码响应
  python wsgr_client.py hello    # 只发 12 字节握手, 看服务端回应
"""
import os
import socket
import struct
import sys
import time

CAP = r"C:\Users\26912\Projects\wsgr-rt\capture\f10010"
HOST = "xr-server-2.moefantasy.com"
PORT = 10010
KEY = 0xAE


def crypt(b):
    return bytes(x ^ KEY for x in b)


def hexdump(b, n=320):
    out = []
    for i in range(0, min(len(b), n), 16):
        ch = b[i:i + 16]
        out.append("  %04x  %-47s  %s" % (i, " ".join("%02x" % c for c in ch),
                   "".join(chr(c) if 32 <= c < 127 else "." for c in ch)))
    if len(b) > n:
        out.append("  ... 共 %d 字节" % len(b))
    return "\n".join(out)


def unframe(buf):
    """按 <6字节头><u32 len><payload> 切分 (buf 应为已解密的明文)."""
    msgs, off = [], 0
    while off + 10 <= len(buf):
        hdr = buf[off:off + 6]
        (ln,) = struct.unpack_from("<I", buf, off + 6)
        if ln > 0x100000 or off + 10 + ln > len(buf):
            msgs.append(("BAD", hdr, ln, buf[off + 10:off + 10 + min(max(ln, 0), 64)]))
            break
        msgs.append(("OK", hdr, ln, buf[off + 10:off + 10 + ln]))
        off += 10 + ln
    return msgs


def conn():
    s = socket.socket()
    s.settimeout(12)
    s.connect((HOST, PORT))
    print("[+] 已连接 %s:%d" % (HOST, PORT))
    return s


def drain(s, secs=6):
    total = b""
    end = time.time() + secs
    s.settimeout(1.5)
    while time.time() < end:
        try:
            c = s.recv(65536)
        except socket.timeout:
            if total:
                break
            continue
        except Exception as e:
            print("  recv 异常: %s" % e)
            break
        if not c:
            break
        total += c
        if len(total) > 400000:
            break
    return total


def report(raw, title):
    print("\n" + "=" * 90)
    print("### %s  密文 %d 字节" % (title, len(raw)))
    plain = crypt(raw)
    print("--- 解密后 (XOR 0xAE) ---")
    print(hexdump(plain))
    msgs = unframe(plain)
    print("--- 帧切分: %d 条 ---" % len(msgs))
    for kind, hdr, ln, body in msgs[:20]:
        print("  [%s] hdr=%s len=%-6d body=%s" % (
            kind, hdr.hex(" "), ln,
            "".join(chr(c) if 32 <= c < 127 else "." for c in body[:110])))


def cmd_replay():
    req = open(os.path.join(CAP, "10.0.2.15_S_C_53568.bin"), "rb").read()
    hello = open(os.path.join(CAP, "10.0.2.15_S_C_40396.bin"), "rb").read()
    s = conn()
    for label, pkt in (("12 字节握手", hello), ("362 字节进入游戏请求", req)):
        s.sendall(pkt)
        print("[>] 发送 %s (%d 字节)" % (label, len(pkt)))
        time.sleep(0.8)
    resp = drain(s)
    s.close()
    if resp:
        report(resp, "服务端响应")
    else:
        print("(无响应)")


def cmd_hello():
    hello = open(os.path.join(CAP, "10.0.2.15_S_C_40396.bin"), "rb").read()
    s = conn()
    s.sendall(hello)
    print("[>] 发送 12 字节握手")
    resp = drain(s, 5)
    s.close()
    if resp:
        report(resp, "握手响应")
    else:
        print("(无响应)")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "replay"
    if cmd == "replay":
        cmd_replay()
    else:
        cmd_hello()
