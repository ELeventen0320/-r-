# -*- coding: utf-8 -*-
"""
★ 战舰少女R 脱机挂机客户端 v2 ★

相比 v1 的改进:
  1) 解析响应状态码 (不再无脑发请求, 记录每次动作成败)
  2) 自动重连 (断线指数退避重试)
  3) 心跳严格 5 秒; 动作按可配置间隔执行 (默认 5 分钟, 而非每条推送都发)
  4) 支持配置文件 config.json (远征列表 / 舰队 / 间隔)
  5) 长跑模式: 循环执行并输出统计

协议 (全部实测确认):
  加密 = 明文 XOR 0xAE
  帧   = <u32 LE 总长度 L(含自身4字节)> + (L-4) 字节内容
  内容 = <u16 LE 消息ID> + <字段>
  填充 = 帧间可夹 0xAE

已确认消息 ID:
  1     保活心跳 (每 5 秒)        5003  登录
  7091  领取每日签到奖励           7132  派遣/继续远征  field1=舰队 field2=远征
  7136  领取远征奖励  field1=远征

服务端:
  3397  心跳 ack (每 5 秒)         5957  周期推送 (每 15 秒, 带服务器时间戳)
  5701 / 7493  动作响应, 内含内层 msgid + 08 <状态码>
  4933  派遣响应 (内含 7133)
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
GAME_HOST = "xr-server-2.moefantasy.com"
GAME_PORT = 10010
SELF = os.path.dirname(os.path.abspath(__file__))
CAP = os.path.abspath(os.path.join(SELF, "..", "capture"))

MSG_KEEPALIVE = 1
MSG_EXPEDITION_DISPATCH = 7132
MSG_EXPEDITION_CLAIM = 7136
# 服务端响应里出现的内层 msgid
RESP_CLAIM = 7137
RESP_DISPATCH = 7133


# ---------------- 编解码 ----------------
def crypt(b):
    return bytes(x ^ KEY for x in b)


def varint(v):
    out = b""
    while True:
        b = v & 0x7F
        v >>= 7
        out += bytes([b | 0x80]) if v else bytes([b])
        if not v:
            return out


def rd_varint(b, i):
    v = 0
    shift = 0
    while i < len(b):
        c = b[i]; i += 1
        v |= (c & 0x7F) << shift
        if not (c & 0x80):
            return v, i
        shift += 7
    return None, i


def f_varint(field, value):
    return bytes([(field << 3) | 0]) + varint(value)


def build(msgid, fields=b"", trailer=None):
    content = struct.pack("<H", msgid) + fields
    if trailer is None and fields:
        trailer = len(fields) + 3
    if trailer is not None:
        content += struct.pack("<I", trailer)
    return struct.pack("<I", len(content) + 4) + content


def parse_frames(buf, start=0):
    frames, off, n = [], start, len(buf)
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


def inner_status(content):
    """从响应内容里提取内层 msgid 与状态码 (08 <varint>).
    注意: 内层消息可能落在任意(含奇数)偏移, 必须全偏移扫描.
    """
    res = []
    for base in range(0, max(0, min(len(content) - 4, 40))):
        mid = struct.unpack_from("<H", content, base)[0]
        if mid in (RESP_CLAIM, RESP_DISPATCH):
            sub = content[base + 2:]
            i = 0
            st = None
            while i < len(sub) - 1:
                if sub[i] == 0x08:
                    v, i = rd_varint(sub, i + 1)
                    st = v
                    break
                i += 1
            res.append((mid, st))
    return res


# ---------------- HTTP ----------------
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


def load_config():
    p = os.path.join(SELF, "config.json")
    cfg = json.load(open(p, encoding="utf-8")) if os.path.exists(p) else {}
    # 保守默认值 —— 见文档「动作通道限流」一节:
    # 高频动作会导致服务端静默忽略动作(连接与心跳仍正常), 故默认 15 分钟 + 抖动
    cfg.setdefault("expeditions", [10001])
    cfg.setdefault("fleet", 6)
    cfg.setdefault("action_interval", 900)
    cfg.setdefault("jitter", 120)
    cfg.setdefault("server", GAME_HOST)
    cfg.setdefault("port", GAME_PORT)
    return cfg


def login_frames():
    """取出完整的登录块 (含 7007/7012 两个 10 字节握手帧).
    之前只发 ln>10 的帧, 丢掉了握手帧 —— 那是动作被服务端忽略的原因.
    """
    p = os.path.join(CAP, "f10010", "10.0.2.15_S_C_53568.bin")
    raw = open(p, "rb").read()
    fr = parse_frames(crypt(raw), 0)
    out = []
    for off, ln, _ in fr:
        if ln == 6 and out:          # 登录块结束, 后面都是保活
            break
        out.append((ln, raw[off:off + ln]))
    return out


# ---------------- 客户端 ----------------
class Client:
    def __init__(self, cfg, log):
        self.cfg = cfg
        self.log = log
        self.s = None
        self.last_ka = 0.0
        self.ka = crypt(build(MSG_KEEPALIVE, b"", trailer=None))
        self.stats = {"claim_ok": 0, "claim_fail": 0, "dispatch": 0, "reconnect": 0}

    def connect(self):
        host = self.cfg.get("server", GAME_HOST)
        port = self.cfg.get("port", GAME_PORT)
        self.s = socket.socket()
        self.s.settimeout(2.0)
        self.s.connect((host, port))
        self.log("已连接 %s:%d" % (host, port))
        for ln, pkt in login_frames():
            self.s.sendall(pkt)
            self.log('  [>] 登录帧 len=%d' % ln)
            time.sleep(0.3)
        time.sleep(1.5)
        self.drain(max_wait=1.5)
        self.last_ka = time.time()

    def close(self):
        try:
            if self.s:
                self.s.close()
        except Exception:
            pass
        self.s = None

    def send(self, plain_pkt):
        self.s.sendall(crypt(plain_pkt))

    def drain(self, max_wait=1.0):
        """收包直到超时; 返回收到的帧列表."""
        got = []
        end = time.time() + max_wait
        while time.time() < end:
            try:
                c = self.s.recv(65536)
            except socket.timeout:
                break
            except Exception as e:
                raise IOError(str(e))
            if not c:
                raise IOError("connection closed")
            for off, ln, content in parse_frames(crypt(c), 0):
                got.append((ln, content))
        return got

    def pump(self, timeout=1.0):
        self.s.settimeout(timeout)
        now = time.time()
        if now - self.last_ka >= 5:
            self.s.sendall(self.ka)
            self.last_ka = now
        try:
            c = self.s.recv(65536)
        except socket.timeout:
            return []
        if not c:
            raise IOError("connection closed")
        return parse_frames(crypt(c), 0)

    def claim(self, expedition):
        f = f_varint(1, expedition)
        self.send(build(MSG_EXPEDITION_CLAIM, f, trailer=len(f) + 3))
        self.log("  [>] 领取远征奖励 远征=%d" % expedition)
        time.sleep(1.0)
        got = self.drain(max_wait=2.5)
        self.log("  [dbg] 收到 %d 帧: %s" % (
            len(got), [struct.unpack_from("<H", c, 0)[0] for _, c in got]))
        for ln, content in got:
            self.log("  [dbg] len=%d hex=%s" % (ln, content[:24].hex(" ")))
            for mid, st in inner_status(content):
                if mid == RESP_CLAIM:
                    ok = (st == 22)
                    self.stats["claim_ok" if ok else "claim_fail"] += 1
                    self.log("  [<] 领取结果 状态码=%s %s" % (st, "OK" if ok else "FAIL"))
                    return ok
        self.stats["claim_fail"] += 1
        self.log("  [<] 领取无响应或未识别")
        return False

    def dispatch(self, fleet, expedition):
        f = f_varint(1, fleet) + f_varint(2, expedition)
        self.send(build(MSG_EXPEDITION_DISPATCH, f, trailer=len(f) + 2))
        self.log("  [>] 派遣远征 舰队=%d 远征=%d" % (fleet, expedition))
        time.sleep(1.0)
        for ln, content in self.drain(max_wait=2.0):
            for mid, st in inner_status(content):
                if mid == RESP_DISPATCH:
                    self.stats["dispatch"] += 1
                    self.log("  [<] 派遣结果 状态码=%s" % st)
                    return True
        return False


def run(cfg, seconds, log):
    c = Client(cfg, log)
    t0 = time.time()
    last_action = 0
    exps = cfg.get("expeditions", [10001])
    fleet = cfg.get("fleet", 6)
    import random
    interval = cfg.get("action_interval", 900)
    jitter = cfg.get("jitter", 120)
    next_action = time.time() + random.uniform(0, jitter)
    while time.time() - t0 < seconds:
        try:
            if c.s is None:
                c.connect()
            frames = c.pump()
            for off, ln, content in frames:
                mid = struct.unpack_from("<H", content, 0)[0] if len(content) >= 2 else -1
                if mid in (5957, 6469):
                    log("  [<] 推送 msgid=%d (%d 字节)" % (mid, ln))
            now = time.time()
            if now >= next_action:
                for e in exps:
                    c.claim(e)
                    c.dispatch(fleet, e)
                next_action = now + interval + random.uniform(0, jitter)
                log("  [i] 统计 %s" % c.stats)
        except IOError as e:
            log("  [!] 断开 (%s), 5 秒后重连" % e)
            c.close()
            c.stats["reconnect"] += 1
            time.sleep(5)
    c.close()
    log("结束. 统计 %s, 运行 %.0f 秒" % (c.stats, time.time() - t0))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["login", "claim", "dispatch", "afk"])
    ap.add_argument("expedition", nargs="?", type=int)
    ap.add_argument("fleet", nargs="?", type=int)
    ap.add_argument("--seconds", type=int, default=90)
    ap.add_argument("--interval", type=int, default=None)
    a = ap.parse_args()

    def log(m):
        print("[%s] %s" % (time.strftime("%H:%M:%S"), m))

    tok = load_token()
    if not tok:
        print("!! 缺少 probe/token.txt"); return
    log("认证 ...")
    log("  " + do_auth(tok)[:120])

    cfg = load_config()
    if a.expedition:
        cfg["expeditions"] = [a.expedition]
    if a.fleet:
        cfg["fleet"] = a.fleet
    if a.interval is not None:
        cfg["action_interval"] = a.interval

    if a.cmd == "afk":
        run(cfg, a.seconds, log)
        return

    c = Client(cfg, log)
    c.connect()
    if a.cmd == "claim":
        c.claim(cfg["expeditions"][0])
    elif a.cmd == "dispatch":
        c.dispatch(cfg["fleet"], cfg["expeditions"][0])
    t0 = time.time()
    while time.time() - t0 < a.seconds:
        for off, ln, content in c.pump():
            mid = struct.unpack_from("<H", content, 0)[0] if len(content) >= 2 else -1
            log("  [<] msgid=%d (%d 字节)" % (mid, ln))
    c.close()


if __name__ == "__main__":
    main()
