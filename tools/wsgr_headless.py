# -*- coding: utf-8 -*-
"""
★ 战舰少女R 脱机客户端 (完整链路) ★

流程:
  1. POST http://xrpc.moefantasy.com/            -> 服务器列表 (zlib JSON)
  2. POST http://xr-server-N.moefantasy.com:10005/auth/  -> 账号信息 (明文 JSON)
  3. TCP  xr-server-N.moefantasy.com:10010       -> 游戏主协议 (XOR 0xAE)

凭据不写进代码: 从 --token 参数或同目录 token.txt 读取.

用法:
  python wsgr_headless.py list                 # 只取服务器列表
  python wsgr_headless.py auth  --token XXXX   # 认证
  python wsgr_headless.py login --token XXXX   # 完整: 列表+认证+连游戏服
"""
import argparse
import json
import os
import socket
import struct
import sys
import time
import urllib.parse
import urllib.request
import zlib

KEY = 0xAE
UA = "Dalvik/2.1.0 (Linux; U; Android 5.1.1; oppo a53 Build/LYZ28N)"
XRPC = "http://xrpc.moefantasy.com/"
SELF_DIR = os.path.dirname(os.path.abspath(__file__))


def crypt(b):
    return bytes(x ^ KEY for x in b)


def http(url, data=None, timeout=20):
    body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, headers={
        "User-Agent": UA, "Accept-Encoding": "identity",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def get_servers(channel="taptap", app_version="v5.6.0"):
    form = ("app_version=%s&app_id=xr_cn_release&os_type=android"
            "&patch_list=%s&channel=%s") % (
        app_version,
        urllib.parse.quote(json.dumps({"data_hd": "0.0.178.1", "main": "0.0.629.1"}, separators=(",", ":"))),
        channel)
    st, raw = http(XRPC, form)
    j = json.loads(zlib.decompress(raw).decode())
    return st, j


def do_auth(host, token, port=10005):
    body = json.dumps({"token": token, "channel": "hm_sdk_android"}, separators=(",", ":"))
    st, raw = http("http://%s:%d/auth/" % (host, port), body)
    return st, raw.decode("utf-8", "replace")


def load_token(arg):
    if arg:
        return arg
    p = os.path.join(SELF_DIR, "token.txt")
    if os.path.exists(p):
        return open(p).read().strip()
    return None


def hexdump(b, n=256):
    out = []
    for i in range(0, min(len(b), n), 16):
        ch = b[i:i + 16]
        out.append("  %04x  %-47s  %s" % (i, " ".join("%02x" % c for c in ch),
                   "".join(chr(c) if 32 <= c < 127 else "." for c in ch)))
    if len(b) > n:
        out.append("  ... 共 %d 字节" % len(b))
    return "\n".join(out)


def walk(plain):
    msgs, off = [], 0
    while off + 10 <= len(plain):
        hdr = plain[off:off + 6]
        (ln,) = struct.unpack_from("<I", plain, off + 6)
        if ln > 0x100000 or off + 10 + ln > len(plain):
            msgs.append(("BAD", off, hdr, ln, plain[off + 10:off + 10 + 48]))
            break
        msgs.append(("OK", off, hdr, ln, plain[off + 10:off + 10 + ln]))
        off += 10 + ln
    return msgs


def game_login(host, port, frame_path):
    """连接游戏服并发送抓到的登录帧."""
    frame = open(frame_path, "rb").read()
    s = socket.socket()
    s.settimeout(15)
    s.connect((host, port))
    print("[+] 已连接 %s:%d" % (host, port))
    s.sendall(frame)
    print("[>] 已发送登录帧 (%d 字节密文)" % len(frame))
    total, end = b"", time.time() + 10
    s.settimeout(2.0)
    while time.time() < end:
        try:
            c = s.recv(65536)
        except socket.timeout:
            if total:
                break
            continue
        except Exception as e:
            print("  recv: %s" % e)
            break
        if not c:
            break
        total += c
        if len(total) > 400000:
            break
    s.close()
    print("[<] 收到 %d 字节密文" % len(total))
    if not total:
        return None
    plain = crypt(total)
    print("--- 解密后 ---")
    print(hexdump(plain, 320))
    msgs = walk(plain)
    print("--- 帧切分: %d 条 ---" % len(msgs))
    for kind, off, hdr, ln, body in msgs[:10]:
        print("  [%s] off=%-7d hdr=%s len=%-6d %s" % (
            kind, off, hdr.hex(" "), ln,
            "".join(chr(c) if 32 <= c < 127 else "." for c in body[:80])))
    return plain


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["list", "auth", "login"])
    ap.add_argument("--token")
    ap.add_argument("--server", default=None, help="游戏服主机名, 默认取列表第一个")
    ap.add_argument("--auth-server", default="xr-server-4.moefantasy.com",
                    help="认证服 (实测只有 xr-server-4 开放 10005)")
    ap.add_argument("--port", type=int, default=10010, help="游戏主协议端口")
    ap.add_argument("--frame", default=os.path.join(
        SELF_DIR, "..", "capture", "f10010", "10.0.2.15_S_C_53568.bin"))
    a = ap.parse_args()

    tok = load_token(a.token)
    host = a.server

    if a.cmd in ("list", "login"):
        st, j = get_servers()
        print("[1] xrpc 服务器列表  HTTP %s" % st)
        for s in j["notice"]["server_list"]:
            print("    id=%-4d %-8s %s:%d" % (s["id"], s["name"], s["ip"], s["port"]))
        if not host:
            host = j["notice"]["server_list"][0]["ip"]
        if a.cmd == "list":
            return
    else:
        host = host or "xr-server-2.moefantasy.com"

    if not tok:
        print("!! 缺少 token (用 --token 或 token.txt)"); return
    st, body = do_auth(a.auth_server, tok)
    print("\n[2] /auth/ @%s  HTTP %s\n    %s" % (a.auth_server, st, body[:300]))

    if a.cmd == "login":
        print("\n[3] 连接游戏主协议 %s:%d" % (host, a.port))
        game_login(host, a.port, os.path.abspath(a.frame))


if __name__ == "__main__":
    main()
