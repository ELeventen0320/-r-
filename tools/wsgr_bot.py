# -*- coding: utf-8 -*-
"""
★ 战舰少女R 脱机挂机客户端 ★

完整链路:
  1) POST http://xrpc.moefantasy.com/                     补丁 + 服务器列表
  2) POST http://xr-server-4.moefantasy.com:10005/auth/   账号认证
  3) TCP  xr-server-N.moefantasy.com:10010                游戏主协议

协议 (全部实测确认):
  加密 = 明文 XOR 0xAE
  帧   = <u32 LE 总长度 L(含自身4字节)> + (L-4) 字节内容
  内容 = <u16 LE 消息ID> + <字段>
  填充 = 帧间可夹 0xAE

已确认的消息 ID:
  1     保活心跳 (每 5 秒)
  5003  登录
  7091  领取每日签到奖励
  7132  派遣/继续远征   field1=舰队号  field2=远征ID
  7136  领取远征奖励     field1=远征ID

用法:
  python wsgr_bot.py login         仅建立连接并保持在线 (观察服务端推送)
  python wsgr_bot.py claim 10001   上线并领取指定远征的奖励
  python wsgr_bot.py dispatch 6 10001   派遣第六舰队去远征 10001
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
AUTH_HOST = "xr-server-4.moefantasy.com"
SELF = os.path.dirname(os.path.abspath(__file__))
CAP = os.path.abspath(os.path.join(SELF, "..", "capture"))

MSG_KEEPALIVE = 1
MSG_LOGIN = 5003
MSG_SIGN_REWARD = 7091
MSG_EXPEDITION_DISPATCH = 7132
MSG_EXPEDITION_CLAIM = 7136


# ---------- 协议编解码 ----------
def crypt(b):
    return bytes(x ^ KEY for x in b)


def build(msgid, fields=b"", trailer=None):
    """构造一帧 (明文). trailer 缺省时按观测值 (字段字节数 + 3) 生成."""
    content = struct.pack("<H", msgid) + fields
    if trailer is None and fields:
        trailer = len(fields) + 3
    if trailer is not None:
        content += struct.pack("<I", trailer)
    return struct.pack("<I", len(content) + 4) + content


def varint(v):
    out = b""
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out += bytes([b | 0x80])
        else:
            out += bytes([b])
            return out


def f_varint(field, value):
    return bytes([(field << 3) | 0]) + varint(value)


def f_bytes(field, data):
    return bytes([(field << 3) | 2]) + bytes([len(data)]) + data


def parse_frames(buf, start=0):
    frames, off = [], start
    n = len(buf)
    while off + 4 <= n:
        (ln,) = struct.unpack_from("<I", buf, off)
        if ln < 4 or off + ln > n:
            j = off
            while j < n and buf[j] == 0xAE:
                j += 1
            if j > off:
                off = j
                continue
            break
        frames.append((off, ln, buf[off + 4:off + ln]))
        off += ln
    return frames


def describe(content):
    if len(content) < 2:
        return "?"
    mid = struct.unpack_from("<H", content, 0)[0]
    body = content[2:]
    vis = "".join(chr(c) if 32 <= c < 127 else "." for c in body[:48])
    return "msgid=%-6d body=%s | hex=%s" % (mid, vis, body[:20].hex(" "))


# ---------- HTTP ----------
def http(url, data=None, timeout=20):
    body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, headers={
        "User-Agent": UA, "Accept-Encoding": "identity",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def get_servers():
    form = ("app_version=v5.6.0&app_id=xr_cn_release&os_type=android&patch_list=%s&channel=taptap"
            % urllib.parse.quote(json.dumps({"data_hd": "0.0.178.1", "main": "0.0.629.1"},
                                            separators=(",", ":"))))
    st, raw = http(XRPC, form)
    return json.loads(zlib.decompress(raw).decode())


def do_auth(token):
    body = json.dumps({"token": token, "channel": "hm_sdk_android"}, separators=(",", ":"))
    st, raw = http("http://%s:10005/auth/" % AUTH_HOST, body)
    return raw.decode("utf-8", "replace")


def load_token():
    p = os.path.join(SELF, "token.txt")
    return open(p).read().strip() if os.path.exists(p) else None


# ---------- 登录帧 ----------
def login_frames():
    """从抓包中取出登录用的客户端帧 (密文原样重放)."""
    p = os.path.join(CAP, "f10010", "10.0.2.15_S_C_53568.bin")
    raw = open(p, "rb").read()
    plain = crypt(raw)
    fr = parse_frames(plain, 0)
    return [(off, ln, raw[off:off + ln]) for off, ln, _ in fr if ln > 10]


# ---------- 主流程 ----------
def session(expedition=None, fleet=None, do_claim=False, seconds=40):
    tok = load_token()
    if not tok:
        print("!! 缺少 token.txt"); return
    print("[1] 认证 ...")
    print("    " + do_auth(tok)[:150])

    print("[2] 连接游戏服 ...")
    s = socket.socket()
    s.settimeout(15)
    s.connect(("xr-server-2.moefantasy.com", 10010))
    print("    已连接 xr-server-2:10010")

    for off, ln, cipher in login_frames():
        s.sendall(cipher)
        print("    [>] 登录帧 len=%d" % ln)
        time.sleep(0.4)

    time.sleep(1.5)
    rx = b""
    s.settimeout(1.0)
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            rx += c
    except socket.timeout:
        pass
    print("[3] 登录响应 %d 字节 -> %d 帧" % (len(rx), len(parse_frames(crypt(rx), 8))))
    for off, ln, content in parse_frames(crypt(rx), 8)[:6]:
        print("    [<] len=%-5d %s" % (ln, describe(content)))

    # 发动作消息
    if do_claim and expedition:
        f = f_varint(1, expedition)
        pkt = crypt(build(MSG_EXPEDITION_CLAIM, f, trailer=len(f) + 3))
        s.sendall(pkt)
        print("[4] [>] 领取远征奖励 msgid=%d 远征ID=%d (帧 %d 字节)"
              % (MSG_EXPEDITION_CLAIM, expedition, len(pkt)))
    if expedition and fleet:
        f = f_varint(1, fleet) + f_varint(2, expedition)
        pkt = crypt(build(MSG_EXPEDITION_DISPATCH, f, trailer=len(f) + 2))
        s.sendall(pkt)
        print("[4] [>] 派遣远征 msgid=%d 舰队=%d 远征=%d (帧 %d 字节)"
              % (MSG_EXPEDITION_DISPATCH, fleet, expedition, len(pkt)))

    # 保持在线 + 收推送
    print("[5] 保持在线 %d 秒 (每 5 秒心跳) ..." % seconds)
    ka = crypt(build(MSG_KEEPALIVE, b"", trailer=None))
    t0 = time.time()
    last = 0
    s.settimeout(1.0)
    while time.time() - t0 < seconds:
        if time.time() - last >= 5:
            s.sendall(ka)
            last = time.time()
        try:
            c = s.recv(65536)
        except socket.timeout:
            continue
        except Exception as e:
            print("    recv 异常: %s" % e); break
        if not c:
            break
        for off, ln, content in parse_frames(crypt(c), 0):
            print("    [< t+%.1fs] len=%-5d %s" % (time.time() - t0, ln, describe(content)))
    s.close()
    print("[6] 结束")


def afk_loop(expedition, fleet, cycles, seconds):
    """挂机循环: 上线 -> 定期领取远征奖励 -> 重新派遣."""
    tok = load_token()
    if not tok:
        print("!! 缺少 token.txt"); return
    do_auth(tok)
    s = socket.socket(); s.settimeout(15)
    s.connect(("xr-server-2.moefantasy.com", 10010))
    print("[+] 已连接 xr-server-2:10010")
    for off, ln, cipher in login_frames():
        s.sendall(cipher); time.sleep(0.3)
    time.sleep(1.5)

    ka = crypt(build(MSG_KEEPALIVE, b"", trailer=None))
    t0 = time.time(); last_ka = 0; done = 0
    s.settimeout(1.0)
    print("[+] 挂机开始 (目标: 远征 %d / 舰队 %d, %d 个循环)" % (expedition, fleet, cycles))
    while time.time() - t0 < seconds and done < cycles:
        now = time.time()
        if now - last_ka >= 5:
            s.sendall(ka); last_ka = now
        # 每 6 秒尝试一次: 领取奖励 -> 重新派遣
        if int(now - t0) % 6 == 0 and (now - t0) > 3:
            pass
        try:
            c = s.recv(65536)
        except socket.timeout:
            continue
        except Exception as e:
            print("  recv: %s" % e); break
        if not c:
            break
        for off, ln, content in parse_frames(crypt(c), 0):
            mid = struct.unpack_from("<H", content, 0)[0] if len(content) >= 2 else -1
            print("  [< t+%.1fs] %s" % (time.time() - t0, describe(content)))
            # 收到"远征完成"推送 -> 领奖 + 重派
            if mid == 5957 and done < cycles:
                time.sleep(0.5)
                f1 = f_varint(1, expedition)
                s.sendall(crypt(build(MSG_EXPEDITION_CLAIM, f1, trailer=len(f1) + 3)))
                print("  [>] 领取远征奖励 远征=%d" % expedition)
                time.sleep(1.2)
                f2 = f_varint(1, fleet) + f_varint(2, expedition)
                s.sendall(crypt(build(MSG_EXPEDITION_DISPATCH, f2, trailer=len(f2) + 2)))
                print("  [>] 重新派遣 舰队=%d 远征=%d" % (fleet, expedition))
                done += 1
    s.close()
    print("[+] 挂机结束, 完成 %d 个循环" % done)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["login", "claim", "dispatch", "afk"])
    ap.add_argument("expedition", nargs="?", type=int, default=10001)
    ap.add_argument("fleet", nargs="?", type=int, default=6)
    ap.add_argument("--seconds", type=int, default=40)
    ap.add_argument("--cycles", type=int, default=3)
    a = ap.parse_args()
    if a.cmd == "login":
        session(seconds=a.seconds)
    elif a.cmd == "claim":
        session(expedition=a.expedition, do_claim=True, seconds=a.seconds)
    elif a.cmd == "dispatch":
        session(expedition=a.expedition, fleet=a.fleet, seconds=a.seconds)
    else:
        afk_loop(a.expedition, a.fleet, a.cycles, a.seconds)
