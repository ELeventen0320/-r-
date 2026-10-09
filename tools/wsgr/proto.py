# -*- coding: utf-8 -*-
"""
wsgr.proto —— 战舰少女R 现行协议编解码

传输层规格 (已在 3 条真实流上 100% 验证):
  加密 : 密文 = 明文 XOR 0xAE            (单字节, 全局固定)
  帧   : <u32 LE 总长度 L, 含自身 4 字节> + (L-4) 字节内容
  填充 : 帧之间可夹 0xAE 填充, 解码时跳过

应用层规格:
  帧内容 = <u16 LE 消息ID> + <字段序列>
  字段   = <tag><值>, tag = (field<<3)|wiretype
           wiretype=2 -> 后跟 1 字节长度, 再跟该长度的数据
"""
import struct

KEY = 0xAE

# ---- 已实测的消息 ID ----
MSG_KEEPALIVE = 1
MSG_LOGIN = 5003
MSG_SIGN_REWARD = 7091
MSG_EXPEDITION_DISPATCH = 7132
MSG_EXPEDITION_CLAIM = 7136

# 服务端响应里出现的内层消息号
RESP_CLAIM = 7137
RESP_DISPATCH = 7133

# 服务端推送
SRV_ACK = 3397          # 心跳 ack
SRV_PUSH = 5957         # 周期推送 (每 15 秒, 带服务器时间戳)
SRV_WELCOME = 11589     # 登录欢迎 (带会话密钥)
SRV_CONFIG = 27205      # 客户端配置 JSON


# ---------------- 加解密 ----------------
def decrypt(cipher: bytes) -> bytes:
    return bytes(x ^ KEY for x in cipher)


def encrypt(plain: bytes) -> bytes:
    return bytes(x ^ KEY for x in plain)


# ---------------- 帧 ----------------
def build_frame(content: bytes) -> bytes:
    return struct.pack("<I", len(content) + 4) + content


def parse_frames(buf: bytes, start: int = 0):
    """切分帧; 长度非法时跳过连续的 0xAE 填充后重试.
    返回 [(offset, length, content), ...]
    """
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


# ---------------- 应用层 ----------------
def varint(v: int) -> bytes:
    out = b""
    while True:
        b = v & 0x7F
        v >>= 7
        out += bytes([b | 0x80]) if v else bytes([b])
        if not v:
            return out


def rd_varint(b: bytes, i: int):
    v, shift = 0, 0
    while i < len(b):
        c = b[i]
        i += 1
        v |= (c & 0x7F) << shift
        if not (c & 0x80):
            return v, i
        shift += 7
    return None, i


def f_varint(field: int, value: int) -> bytes:
    return bytes([(field << 3) | 0]) + varint(value)


def f_bytes(field: int, data: bytes) -> bytes:
    return bytes([(field << 3) | 2]) + bytes([len(data)]) + data


def build_message(msgid: int, fields: bytes = b"", trailer=None) -> bytes:
    """构造一条应用层消息 (明文).

    trailer: 观测到的 4 字节尾部. 缺省按「字段字节数 + 常数」推算:
      单字段 (7136) -> +3      双字段 (7132) -> +2
    实测两种都能被服务端接受; 保守起见按观测值生成.
    """
    content = struct.pack("<H", msgid) + fields
    if trailer is None and fields:
        trailer = len(fields) + (3 if fields.count(0x08) + fields.count(0x10) <= 1 else 2)
    if trailer is not None:
        content += struct.pack("<I", trailer)
    return build_frame(content)


def msgid_of(content: bytes) -> int:
    return struct.unpack_from("<H", content, 0)[0] if len(content) >= 2 else -1


def find_inner(content: bytes, want_ids):
    """在响应内容里寻找内层消息 (可能落在任意偏移, 含奇数).

    返回 [(msgid, 首个字段值), ...]
    """
    out = []
    for base in range(0, max(0, len(content) - 3)):
        mid = struct.unpack_from("<H", content, base)[0]
        if mid in want_ids:
            sub = content[base + 2:]
            val = None
            i = 0
            while i < len(sub) - 1:
                if sub[i] == 0x08:
                    val, i = rd_varint(sub, i + 1)
                    break
                i += 1
            out.append((mid, val))
    return out


# ---- 动作构造 ----
def claim_expedition(expedition_id: int) -> bytes:
    """领取远征奖励 (msgid 7136, field1 = 远征ID)."""
    f = f_varint(1, expedition_id)
    return build_message(MSG_EXPEDITION_CLAIM, f, trailer=len(f) + 3)


def dispatch_expedition(fleet: int, expedition_id: int) -> bytes:
    """派遣 / 继续远征 (msgid 7132, field1 = 舰队, field2 = 远征ID)."""
    f = f_varint(1, fleet) + f_varint(2, expedition_id)
    return build_message(MSG_EXPEDITION_DISPATCH, f, trailer=len(f) + 2)


def keepalive() -> bytes:
    return build_message(MSG_KEEPALIVE, b"", trailer=None)
