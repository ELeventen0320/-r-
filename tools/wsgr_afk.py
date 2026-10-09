# -*- coding: utf-8 -*-
"""
★ 战舰少女R 脱机脚本 (完整版) ★

用法:
  python wsgr_afk.py info                     查看服务器列表 + 校验 token
  python wsgr_afk.py login  [--seconds 60]     上线并保持在线 (观察推送)
  python wsgr_afk.py claim  <远征ID>            领取一次远征奖励
  python wsgr_afk.py dispatch <舰队> <远征ID>    派遣一次远征
  python wsgr_afk.py run    [--seconds 0]      挂机 (0 = 无限)

架构:
  wsgr.proto      协议编解码 (XOR 0xAE + 帧 + 应用层消息)
  wsgr.bootstrap  HTTP 引导 (服务器列表 / 认证)
  wsgr.session    游戏服会话 (登录 / 心跳 / 收发 / 重连)
  wsgr.tasks      任务系统 (远征 / 签到 / 可扩展)
  wsgr.ctx        配置与日志
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wsgr import bootstrap, ctx as ctxmod, inspect as inspectmod, proto
from wsgr import server as srvmod
from wsgr import session as sessmod, tasks


def cmd_info(c):
    notice = bootstrap.get_notice()
    c.log("服务器列表:")
    for sid, name, host, port in bootstrap.server_list(notice):
        c.log("  id=%-4d %-8s %s:%d" % (sid, name, host, port))
    tok = c.load_token()
    if not tok:
        c.log("!! 未找到 token (%s)" % c.cfg["token_file"])
        c.log("   请先在游戏内登录一次, 然后从设备读取 hm_token")
        return 1
    try:
        info = bootstrap.auth(tok)
        c.log("token 有效. 账号=%s account_id=%s"
              % (info.get("account_name"), info.get("account_id")))
        played = srvmod.last_played(info)
        if played:
            c.log("账号游玩记录 (服务器ID -> 最后登录, 按新到旧):")
            for sid, ts in played[:6]:
                c.log("   id=%-4d %s  (%d 秒前)"
                      % (sid, time.strftime("%m-%d %H:%M:%S",
                                            time.localtime(ts)),
                         int(time.time()) - ts))
        act = srvmod.active_server(info, notice)
        if act:
            host, port = srvmod.game_endpoint(notice, act["id"])
            c.log("=> 当前服务器: id=%s %s  \u2192 %s:%s"
                  % (act["id"], act["name"], host, port))
        return 0
    except bootstrap.AuthError as e:
        c.log("!! %s" % e)
        c.log("   => token 已失效, 需要重新从游戏客户端获取")
        return 2


def resolve_server(c):
    """根据 auth 的游玩记录自动选择服务器 (失败则回退到配置值)."""
    try:
        info = bootstrap.auth(c.load_token())
        notice = bootstrap.get_notice()
        act = srvmod.active_server(info, notice)
        if act:
            host, port = srvmod.game_endpoint(notice, act["id"])
            if host:
                c.log("自动选服: id=%s %s -> %s:%s"
                      % (act["id"], act["name"], host, port))
                return host, port
    except Exception as e:
        c.log("自动选服失败, 回退配置: %s" % e)
    return c.cfg["server"], c.cfg["port"]


def make_session(c):
    host, port = resolve_server(c)
    return sessmod.Session(
        c.load_token(),
        host=host, port=port,
        login_frame_path=c.cfg["login_frame"], log=c.log)


def cmd_login(c, seconds):
    s = make_session(c)
    s.verify_token()
    s.connect()
    t0 = time.time()
    try:
        while time.time() - t0 < seconds:
            for mid, ln, content in s.pump():
                c.log("  [<] msgid=%-6d (%d 字节)" % (mid, ln))
    except (sessmod.SessionError, sessmod.TokenExpired) as e:
        c.log("断开: %s" % e)
    finally:
        s.close()
    c.log("统计: %s" % s.stats)
    return 0


def cmd_once(c, kind, voyage, fleet=None):
    s = make_session(c)
    try:
        s.verify_token()
        s.connect()
        if kind == "claim":
            s.do_claim_expedition(voyage)
        else:
            s.do_dispatch_expedition(fleet or 6, voyage)
    except sessmod.TokenExpired as e:
        c.log("!! 凭据失效: %s" % e)
        return 3
    except sessmod.SessionError as e:
        c.log("!! 会话异常: %s" % e)
        return 4
    finally:
        s.close()
    c.log("统计: %s" % s.stats)
    return 0


def cmd_inspect(c, seconds, dump=None):
    """登录后收集推送并输出状态报告."""
    s = make_session(c)
    try:
        s.verify_token()
        s.connect()
        c.log("收集推送 %d 秒 ..." % seconds)
        frames = inspectmod.collect(s, seconds)
        info = inspectmod.report(frames, c.log)
        if dump:
            inspectmod.save_raw(frames, dump)
            c.log("原始帧已保存: %s" % dump)
        return 0 if info["expeditions"] else 5
    except sessmod.TokenExpired as e:
        c.log("!! 凭据失效: %s" % e)
        return 3
    except sessmod.SessionError as e:
        c.log("!! 会话异常: %s" % e)
        return 4
    finally:
        s.close()


def cmd_run(c, seconds):
    """挂机主循环: 断线自动重连, 任务按各自节奏调度."""
    tlist = tasks.default_tasks(c, c.cfg)
    for t in tlist:
        c.log("任务已加载: %s  间隔≈%ds  抖动 [1x,2x)" % (t.name, t.interval))
    s = None
    t0 = time.time()
    last_push = 0.0
    while seconds == 0 or time.time() - t0 < seconds:
        try:
            if s is None or not s.connected:
                s = make_session(c)
                s.verify_token()          # 上线前校验凭据
                s.connect()
                c.ctx_session = s
                c.session = s
                # 配置里远征写 "auto" 时, 用扫描到的真实远征 ID
                for t in tlist:
                    if hasattr(t, "expeditions") and t.expeditions == ["auto"]:
                        if s.expeditions:
                            t.expeditions = list(s.expeditions)
                            c.log("  [i] %s 使用扫描到的远征 %s"
                                  % (t.name, t.expeditions))
                        else:
                            c.log("  [!] %s 未能扫描到远征 ID, 跳过本轮"
                                  % t.name)
                # 每次(重)连都要重置任务的下次执行时间, 避免连上就猛发
                now = time.time()
                for t in tlist:
                    t.schedule(now)
            c.session = s
            for mid, ln, content in s.pump():
                if mid in (proto.SRV_PUSH, proto.SRV_ACK):
                    if mid == proto.SRV_PUSH and time.time() - last_push > 3:
                        last_push = time.time()
                        c.log("  [<] 推送 msgid=%d" % mid)
                else:
                    c.log("  [<] msgid=%-6d (%d 字节)" % (mid, ln))
            for t in tlist:
                t.tick()
        except sessmod.TokenExpired as e:
            c.log("!! 凭据失效: %s" % e)
            c.log("   停止挂机 —— 需要重新获取 token (拿失效凭据继续发动作没有意义)")
            if s:
                s.close()
            return 3
        except (sessmod.SessionError, OSError) as e:
            c.log("!! 连接异常: %s" % e)
            if s:
                s.close()
            s = None
            time.sleep(c.cfg["reconnect_delay"])
    if s:
        s.close()
    for t in tlist:
        c.log("任务 %-12s 执行 %d 次, 失败 %d 次" % (t.name, t.runs, t.fails))
    return 0


def main():
    ap = argparse.ArgumentParser(description="战舰少女R 脱机脚本")
    ap.add_argument("cmd", choices=["info", "login", "claim", "dispatch",
                                        "inspect", "run"])
    ap.add_argument("args", nargs="*", type=int)
    ap.add_argument("--seconds", type=int, default=None)
    ap.add_argument("--config", default=None)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--dump", default=None, help="把原始帧保存到该文件")
    a = ap.parse_args()

    cfg = ctxmod.load_config(a.config)
    c = ctxmod.Ctx(cfg, verbose=not a.quiet)
    logdir = os.path.join(ctxmod.ROOT, "logs")
    os.makedirs(logdir, exist_ok=True)
    c.attach_logfile(os.path.join(logdir, "wsgr_%s.log" % time.strftime("%Y%m%d")))

    if a.cmd == "info":
        return cmd_info(c)
    if a.cmd == "login":
        return cmd_login(c, a.seconds if a.seconds is not None else 60)
    if a.cmd == "claim":
        if not a.args:
            c.log("用法: claim <远征ID>"); return 1
        return cmd_once(c, "claim", a.args[0])
    if a.cmd == "dispatch":
        if len(a.args) < 2:
            c.log("用法: dispatch <舰队> <远征ID>"); return 1
        return cmd_once(c, "dispatch", a.args[1], a.args[0])
    if a.cmd == "inspect":
        return cmd_inspect(c, a.seconds if a.seconds is not None else 15,
                           a.dump)
    if a.cmd == "run":
        return cmd_run(c, a.seconds if a.seconds is not None else 0)
    return 1


if __name__ == "__main__":
    sys.exit(main())
