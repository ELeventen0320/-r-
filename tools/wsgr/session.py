# -*- coding: utf-8 -*-
"""
wsgr.session —— 游戏服会话 (登录 / 心跳 / 收发 / 自动重连)

登录流程 (帧序列来自抓包原样重放, 实测可被服务端接受):
  6, 180, 10, 10, 86, 10, 12 字节 —— 共 7 帧的完整登录块
  ★ 早期版本用 `len > 10` 过滤, 丢掉了两个 10 字节握手帧, 是隐患
"""
import os
import socket
import time

from . import proto
from .bootstrap import auth, AuthError

DEFAULT_HOST = "xr-server-2.moefantasy.com"
DEFAULT_PORT = 10010
KEEPALIVE_INTERVAL = 5.0


class SessionError(Exception):
    pass


class TokenExpired(Exception):
    pass


def patch_login_token(content, token):
    """把登录消息里的 field 4 (tag 0x22) 替换为当前 token.

    ★ 这是关键修复: 抓包里的登录帧烧死了**当时的** token,
      直接重放会导致「连接建立成功、认证却用的是过期凭据」——
      表现为连接正常、心跳照常, 但一发动作就被服务端 RST,
      极易被误判成"服务端限流".
    """
    tb = token.encode()
    for tag in (0x22, 0x12):                     # field4 / field2
        i = content.find(bytes([tag, len(tb)]))
        if i >= 0 and len(content) >= i + 2 + len(tb):
            return content[:i + 2] + tb + content[i + 2 + len(tb):]
    return content                                # 没找到就不动


def load_login_frames(path, token=None):
    """从抓包文件取出完整登录块; 传入 token 则注入当前 token."""
    raw = open(path, "rb").read()
    plain = proto.decrypt(raw)
    out = []
    for off, ln, _ in proto.parse_frames(plain, 0):
        if ln == 6 and out:          # 登录块结束, 之后都是保活
            break
        content = plain[off + 4:off + ln]
        if token and ln > 100:       # 大帧 = 登录消息
            patched = patch_login_token(content, token)
            if patched != content:
                content = patched
        out.append((ln, proto.encrypt(proto.build_frame(content)),
                    proto.seq_of(content)))
    return out


class Session:
    """一条游戏服长连接."""

    def __init__(self, token, host=DEFAULT_HOST, port=DEFAULT_PORT,
                 login_frame_path=None, log=print):
        self.token = token
        self.host = host
        self.port = port
        self.log = log
        self.frame_path = login_frame_path
        self.sock = None
        self.last_ka = 0.0
        self.ka = proto.encrypt(proto.keepalive())
        #: 消息序号 —— 必须递增, 重复/倒退会被服务端静默丢弃
        self.seq = 1
        self.stats = {"sent": 0, "recv": 0, "reconnect": 0, "errors": 0}

    # ---------- 生命周期 ----------
    def verify_token(self):
        """校验 token; 失效则抛 TokenExpired. 动作前必须调用."""
        try:
            return auth(self.token)
        except AuthError as e:
            raise TokenExpired(str(e))

    def connect(self):
        if self.frame_path is None:
            raise SessionError("缺少 login_frame_path")
        self.sock = socket.socket()
        self.sock.settimeout(2.0)
        self.sock.connect((self.host, self.port))
        self.log("已连接 %s:%d" % (self.host, self.port))
        maxseq = 0
        for ln, pkt, seq in load_login_frames(self.frame_path, self.token):
            self.sock.sendall(pkt)
            self.stats["sent"] += 1
            self.log("  [>] 登录帧 len=%-4d seq=%s" % (ln, seq))
            if seq:
                maxseq = max(maxseq, seq)
            time.sleep(0.3)
        # 登录块占用了序号 1..maxseq, 之后从 maxseq+1 开始
        self.seq = maxseq + 1
        self.log("  [i] 下一个消息序号 = %d" % self.seq)
        time.sleep(1.2)
        self.log("  [i] 登录响应帧:")
        for mid, ln, c in self.recv_until_idle(2.0):
            self.log("      msgid=%-6d len=%-6d" % (mid, ln))
        self.last_ka = time.time()

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        finally:
            self.sock = None

    @property
    def connected(self):
        return self.sock is not None

    # ---------- 收发 ----------
    def send(self, plain_msg):
        if not self.sock:
            raise SessionError("未连接")
        self.sock.sendall(proto.encrypt(plain_msg))
        self.stats["sent"] += 1

    def recv_frames(self, wait=1.0):
        """收包直到超时; 返回 [(msgid, length, content)] 与原始字节."""
        out, raw_all = [], b""
        end = time.time() + wait
        while time.time() < end:
            try:
                c = self.sock.recv(65536)
            except socket.timeout:
                break
            except ConnectionResetError:
                raise TokenExpired("服务端重置连接 (通常是凭据失效)")
            except Exception as e:
                raise SessionError(str(e))
            if not c:
                raise SessionError("连接被关闭")
            self.stats["recv"] += len(c)
            raw_all += c
            for off, ln, content in proto.parse_frames(proto.decrypt(c), 0):
                out.append((proto.msgid_of(content), ln, content))
        return out, raw_all

    def recv_until_idle(self, wait=1.0):
        return self.recv_frames(wait)[0]

    def pump(self, timeout=1.0):
        """心跳 + 收一包."""
        if time.time() - self.last_ka >= KEEPALIVE_INTERVAL:
            self.sock.sendall(self.ka)
            self.last_ka = time.time()
        self.sock.settimeout(timeout)
        try:
            c = self.sock.recv(65536)
        except socket.timeout:
            return []
        except ConnectionResetError:
            raise TokenExpired("服务端重置连接")
        if not c:
            raise SessionError("连接被关闭")
        self.stats["recv"] += len(c)
        return [(proto.msgid_of(ct), ln, ct)
                for off, ln, ct in proto.parse_frames(proto.decrypt(c), 0)]

    def drain(self, wait=1.0):
        """丢弃并返回当前积压的数据 (用于清理心跳)."""
        try:
            return self.recv_frames(wait)[0]
        except (SessionError, TokenExpired):
            return []

    # ---------- 动作 ----------
    def do_claim_expedition(self, expedition_id):
        """领取远征奖励; 返回状态码或 None."""
        self.send(proto.claim_expedition(expedition_id, seq=self.seq))
        self.log("  [>] 领取远征奖励 远征=%d seq=%d" % (expedition_id, self.seq))
        self.seq += 1
        time.sleep(0.8)
        frames, _ = self.recv_frames(2.5)
        for mid, ln, content in frames:
            for imid, st in proto.find_inner(content, (proto.RESP_CLAIM,)):
                self.log("  [<] 领取结果 状态码=%s" % st)
                return st
        self.log("  [<] 领取无响应")
        return None

    def do_dispatch_expedition(self, fleet, expedition_id):
        """派遣 / 继续远征; 返回状态码或 None."""
        self.send(proto.dispatch_expedition(fleet, expedition_id, seq=self.seq))
        self.log("  [>] 派遣远征 舰队=%d 远征=%d seq=%d"
                 % (fleet, expedition_id, self.seq))
        self.seq += 1
        time.sleep(0.8)
        frames, _ = self.recv_frames(2.5)
        for mid, ln, content in frames:
            for imid, st in proto.find_inner(content, (proto.RESP_DISPATCH,)):
                self.log("  [<] 派遣结果 状态码=%s" % st)
                return st
        self.log("  [<] 派遣无响应")
        return None
