# -*- coding: utf-8 -*-
"""
wsgr.state —— 从服务端推送里尽力提取游戏状态

现状 (诚实说明):
  服务端把状态打包在大帧里, 内层编码**不是标准 protobuf**
  (通用 protobuf 解码器在 6.5KB 的帧上只能前进 39 字节就被打断).
  作者已定位到"远征记录"并部分解出结构:

      帧内容 = <u16 外层msgid> ... <内层消息...>
      内层消息 = <u16 msgid> <字段...>
        例: 7131 (0x1bdb) = 远征状态
            内含记录: 08 <舰队> 18 <远征ID> 10 <值>

     实测样本 (两份抓包一致):
        0b 08 06 18 91 4e 10 8f c3 c1 cb 06
        len=11, 舰队=6, 远征=10001, 值=1768972687

  但记录形状不止一种 (另一条 10003 的值换算成时间是 2033 年, 不合理),
  因此本模块只做**尽力提取**, 不声称完整解析.
  已解出的字段语义: 舰队号、远征ID 可靠; "值"的含义待定.
"""
import os
import struct
import sys

from . import proto


def varint_at(b, i):
    v, shift = 0, 0
    j = i
    while j < len(b):
        c = b[j]
        j += 1
        v |= (c & 0x7F) << shift
        if not (c & 0x80):
            return v, j
        shift += 7
        if shift > 63:
            return None, i
    return None, i


#: 已确认的内层消息号
INNER_EXPEDITION = 0x1BDB        # 7131 远征状态


def extract_expeditions(frame_contents):
    """从若干帧内容里提取远征记录: [(expedition_id, fleet, value), ...].

    只依赖已实测确认的模式 `18 <id>` 紧跟 `10 <value>`,
    并回溯紧邻的 `08 <fleet>`.
    """
    found = {}
    for content in frame_contents:
        # 在内层消息 7131 附近扫描; 为稳健起见全帧扫描
        n = len(content)
        i = 0
        while i < n - 4:
            if content[i] == 0x18:
                eid, j = varint_at(content, i + 1)
                if eid is not None and j < n - 1 and content[j] == 0x10:
                    val, k = varint_at(content, j + 1)
                    if val is not None and 10000 <= eid <= 99999:
                        fleet = None
                        if i >= 2 and content[i - 2] == 0x08:
                            fleet, _ = varint_at(content, i - 1)
                        found.setdefault(eid, (eid, fleet, val))
                        i = k
                        continue
            i += 1
    return sorted(found.values())


def extract_expedition_ids(frame_contents):
    return [e for e, _, _ in extract_expeditions(frame_contents)]


def scan(session_frames, log=None):
    """从一次登录收到的帧里扫描状态; 返回发现的远征 ID 列表."""
    ids = extract_expedition_ids([c for _, _, c in session_frames])
    if log:
        log("  状态扫描: 发现 %d 个远征 ID %s" % (len(ids), ids))
    return ids
