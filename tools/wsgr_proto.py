# -*- coding: utf-8 -*-
"""
★ 战舰少女R 现行协议编解码库 (已在 3 条真实流上 100% 验证) ★

传输层规格
----------
加密 : 密文 = 明文 XOR 0xAE           (单字节, 全局固定)
帧   : <u32 LE 总长度 L, 含自身 4 字节> + (L-4) 字节内容
填充 : 帧之间可夹 0xAE 填充 (明文 0xAE / 密文全 00), 解码时跳过

已验证:
  服务端->客户端 63,563 B -> 42 帧, 100.0%
  服务端->客户端 72,953 B -> 28 帧, 100.0%
  客户端->服务端    412 B -> 25 帧, 100.0%

链路
----
  1) POST http://xrpc.moefantasy.com/                      补丁 + 服务器列表 (zlib JSON)
  2) POST http://xr-server-4.moefantasy.com:10005/auth/    账号认证 (明文 JSON)
     (实测 10005 只在 xr-server-4 开放)
  3) TCP  xr-server-N.moefantasy.com:10010                 游戏主协议 (本模块)
"""
import struct

KEY = 0xAE
PAD = 0xAE


# ---------- 加解密 ----------
def decrypt(cipher: bytes) -> bytes:
    """密文 -> 明文 (XOR 0xAE)."""
    return bytes(x ^ KEY for x in cipher)


def encrypt(plain: bytes) -> bytes:
    """明文 -> 密文 (XOR 0xAE). 与 decrypt 同构."""
    return bytes(x ^ KEY for x in plain)


# ---------- 帧 ----------
def build_frame(content: bytes) -> bytes:
    """把内容封装成一帧 (明文)."""
    return struct.pack("<I", len(content) + 4) + content


def parse_frames(buf: bytes, start: int = 0, resync: bool = True):
    """
    切分帧. 返回 (frames, consumed, skipped)
      frames: [(offset, length, content), ...]
      consumed: 实际消费到的末端偏移
      skipped:  跳过的填充字节数
    长度非法时, 若 resync=True 则跳过连续的 0xAE 填充后重试.
    """
    frames, off, skipped = [], start, 0
    n = len(buf)
    while off + 4 <= n:
        (ln,) = struct.unpack_from("<I", buf, off)
        if ln < 4 or off + ln > n:
            if resync:
                j = off
                while j < n and buf[j] == PAD:
                    j += 1
                if j > off:
                    skipped += j - off
                    off = j
                    continue
            break
        frames.append((off, ln, buf[off + 4:off + ln]))
        off += ln
    return frames, off, skipped


def show_frame(off, ln, content, width=72):
    vis = "".join(chr(c) if 32 <= c < 127 else "." for c in content[:width])
    return "off=%-7d len=%-6d %s" % (off, ln, vis)


# ---------- 便捷: 从密文直接得到帧 ----------
def frames_from_cipher(cipher: bytes, start: int = 0):
    return parse_frames(decrypt(cipher), start)


if __name__ == "__main__":
    import os
    import sys

    for p in sys.argv[1:]:
        if not os.path.exists(p):
            continue
        raw = open(p, "rb").read()
        plain = decrypt(raw)
        start = 0
        if struct.unpack_from("<I", plain, 0)[0] > len(plain):
            start = 8          # 服务端流以 8 字节 0xAE 开头
        fr, used, sk = parse_frames(plain, start)
        print("### %s  %d 字节 -> %d 帧, 消费 %.1f%%, 填充 %d"
              % (os.path.basename(p), len(raw), len(fr),
                 100.0 * (used - start) / (len(plain) - start), sk))
        for off, ln, c in fr[:25]:
            print("   ", show_frame(off, ln, c))
