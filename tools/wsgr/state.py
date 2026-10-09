# -*- coding: utf-8 -*-
"""
wsgr.state —— 从服务端推送里提取游戏状态

## 内层容器结构 (本轮实测确认)

服务端大帧的内容不是一个整体, 而是**一串内层消息背靠背排列**:

    帧内容 = <u16 外层msgid> <内层消息> <内层消息> ...

内层消息的 msgid **全部落在 0x1b00..0x1bff** (实测样本):

    0x1b5f=7007  0x1b64=7012  0x1b6a=7018  0x1bb3=7091(每日签到)
    0x1b62=7010  0x1b6e=7022  0x1bdb=7131(远征状态)
    0x1be0=7136  0x1be1=7137  0x1be2=7138

而外层的 msgid (3397 / 5957 / 9543 / 11589 / 27205 ...) 在别的区段,
因此「msgid ∈ 0x1bxx」是一个**干净可靠的切分判据**:
实测在 6.5KB / 12KB 的大帧上覆盖率 88% ~ 98%.

## 仍未解出的部分 (如实说明)

内层消息的**字段编码不是标准 protobuf**:
- 通用 protobuf 解码器在 6.5KB 帧上只前进 39 字节就被打断;
- 以 7131 (远征状态) 为例, 内容 46 字节, TLV 解析到第 2 个字段就出现非法 tag;
- 对比两份抓包的同一消息 (46 vs 44 字节), 差异集中在中间,
  说明是**变长字段**, 但具体编码规则未定 (符号名提示与 messagepack 有关).

因此本模块只保证:
  - 内层消息**切分**可靠;
  - 远征 ID 与舰队号**提取**可靠 (模式 `08 <fleet> 18 <id> 10 <value>`);
  - `value` 字段的含义**未确定** (10001 那条换算成时间合理, 另一条不合理).
"""
import os
import struct
import sys

from . import proto

#: 内层消息号区间 (实测)
INNER_LO, INNER_HI = 0x1B00, 0x1BFF

#: 已确认的内层消息号
MSG_EXPEDITION_STATE = 0x1BDB      # 7131 远征状态
MSG_DAILY_SIGN = 0x1BB3            # 7091 每日签到
MSG_CLAIM_REPLY = 0x1BE1           # 7137 领取回执
MSG_DISPATCH_REPLY = 0x1BE2        # 7138
MSG_SERVER_TIME = 0x1B62           # 7010 携带服务器时间戳


def split_inner(body):
    """按 `msgid ∈ 0x1bxx` 切分内层消息.

    返回 [(offset, msgid, content), ...]
    注意: 该判据偶有误命中 (随机字节恰好落在此区间), 但整体覆盖率很高;
          需要精确数据时应优先使用定向提取 (如 extract_expeditions).
    """
    starts = []
    for i in range(len(body) - 1):
        v = struct.unpack_from("<H", body, i)[0]
        if INNER_LO <= v <= INNER_HI:
            starts.append((i, v))
    clean = []
    for pos, mid in starts:
        if clean and pos - clean[-1][0] < 3:
            continue
        clean.append((pos, mid))
    out = []
    for k, (pos, mid) in enumerate(clean):
        end = clean[k + 1][0] if k + 1 < len(clean) else len(body)
        out.append((pos, mid, body[pos + 2:end]))
    return out


def find_messages(frames, msgid):
    """在所有帧里找出指定内层消息的内容."""
    out = []
    for content in frames:
        if len(content) < 8:
            continue
        for pos, mid, c in split_inner(content[2:]):
            if mid == msgid:
                out.append(c)
    return out


def varint_at(b, i):
    v, shift, j = 0, 0, i
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


EXPEDITION_MIN, EXPEDITION_MAX = 10000, 99999


def extract_expeditions(frame_contents):
    """从「远征状态」消息里提取记录: [(远征ID, 舰队, 值), ...].

    只依赖已实测确认的模式:
        `18 <远征ID>`, 并回溯紧邻的 `08 <舰队>`, 其后紧跟 `10 <值>`.
    已确认 10001/10002/10003 三个 ID 在两份独立抓包中稳定复现.
    """
    found = {}
    for content in frame_contents:
        if len(content) < 8:
            continue
        body = content[2:]
        # 优先在「远征状态」消息内找; 找不到则全帧扫描 (兜底)
        regions = [c for _, mid, c in split_inner(body)
                   if mid == MSG_EXPEDITION_STATE] or [body]
        for region in regions:
            i, n = 0, len(region)
            while i < n - 4:
                if region[i] == 0x18:
                    eid, j = varint_at(region, i + 1)
                    if (eid is not None and j < n - 1 and region[j] == 0x10
                            and EXPEDITION_MIN <= eid <= EXPEDITION_MAX):
                        val, k = varint_at(region, j + 1)
                        if val is not None:
                            fleet = None
                            if i >= 2 and region[i - 2] == 0x08:
                                fleet, _ = varint_at(region, i - 1)
                            found.setdefault(eid, (eid, fleet, val))
                            i = k
                            continue
                i += 1
    return sorted(found.values())


def extract_expedition_ids(frame_contents):
    return [e for e, _, _ in extract_expeditions(frame_contents)]


def extract_server_time(frame_contents):
    """从 7010 消息里取服务器时间戳 (字段 1, varint)."""
    for c in find_messages(frame_contents, MSG_SERVER_TIME):
        if c and c[0] == 0x08:
            v, _ = varint_at(c, 1)
            if v:
                return v
    return None
