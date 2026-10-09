# -*- coding: utf-8 -*-
"""
wsgr.inspect —— 状态检查器

登录后收集若干秒的服务端推送, 输出:
  - 外层帧清单 (msgid / 长度)
  - 内层消息清单 (按 0x1bxx 切分)
  - 提取到的远征记录 (ID / 舰队 / 值)
  - 服务器时间戳, 以及与本地时间的偏差
  - 本地时间与服务器时间的对照 (可用于校正判断"远征是否完成")

这是后续所有状态相关工作 (成败判据 / 自动决策) 的基础工具。
"""
import collections
import os
import struct
import sys
import time

from . import proto, state


def collect(session, seconds=12):
    """登录后收集 seconds 秒的推送."""
    frames = list(getattr(session, "initial_frames", []) or [])
    t0 = time.time()
    while time.time() - t0 < seconds:
        try:
            frames.extend(session.pump(timeout=1.0))
        except Exception as e:
            session.log("  收包中断: %s" % e)
            break
    return frames


def report(frames, log):
    log("=" * 70)
    log("外层帧统计 (共 %d 条)" % len(frames))
    outer = collections.Counter(mid for mid, _, _ in frames)
    for mid, c in outer.most_common(12):
        log("   msgid=%-7d x%d" % (mid, c))

    big = [(mid, ln, c) for mid, ln, c in frames if ln > 1000]
    log("大帧 (len>1000): %d 条" % len(big))

    inner = collections.Counter()
    for mid, ln, c in big:
        for _, imid, _ in state.split_inner(c[2:]):
            inner[imid] += 1
    log("内层消息 (0x1bxx): %d 种, 共 %d 条"
        % (len(inner), sum(inner.values())))
    for imid, c in inner.most_common(20):
        log("   0x%04x %-7d x%d" % (imid, imid, c))

    contents = [c for _, _, c in frames]
    recs = state.extract_expeditions(contents)
    log("远征记录: %d 条" % len(recs))
    for eid, fleet, val in recs:
        log("   远征=%-7d 舰队=%-5s 值=%d" % (eid, fleet, val))

    st = state.extract_server_time(contents)
    if st:
        local = int(time.time())
        log("服务器时间戳 = %d (%s UTC)"
            % (st, time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(st))))
        log("本地时间戳   = %d (%s UTC)  偏差 %+d 秒"
            % (local, time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(local)),
               st - local))
        log("→ 判定「远征是否完成」应以服务器时间为准")

    return {"outer": outer, "inner": inner, "expeditions": recs,
            "server_time": st}


def save_raw(frames, path):
    """把收到的原始(明文)帧内容按序落盘, 便于离线分析."""
    with open(path, "wb") as f:
        for mid, ln, c in frames:
            f.write(struct.pack("<HI", mid & 0xFFFF, len(c)) + c)
    return path
