# -*- coding: utf-8 -*-
"""
wsgr.tasks —— 任务系统

每个任务是一个可独立调度、可插拔的单元:
  - 自己决定"该不该做"(should_run)
  - 自己决定"做什么"(run)
  - 自己报告成败

新增玩法只需要再写一个 Task 子类并注册, 无需改动框架.
"""
import random
import time


class Task:
    name = "task"
    #: 最短执行间隔(秒). 会被 [min_interval, min_interval*2) 的抖动放大
    interval = 900

    def __init__(self, ctx):
        self.ctx = ctx
        self.log = ctx.log
        self.next_at = 0.0
        self.runs = 0
        self.fails = 0

    # ---- 调度 ----
    def schedule(self, now=None):
        now = now or time.time()
        self.next_at = now + self.interval * random.uniform(1.0, 2.0)

    def due(self, now=None):
        return (now or time.time()) >= self.next_at

    # ---- 子类实现 ----
    def should_run(self):
        return True

    def run(self):
        raise NotImplementedError

    def tick(self):
        """到点则执行一次; 返回 True 表示执行了."""
        if not self.due():
            return False
        self.schedule()
        if not self.should_run():
            return False
        self.runs += 1
        try:
            ok = self.run()
            if ok is False:
                self.fails += 1
            return True
        except Exception as e:
            self.fails += 1
            self.log("[%s] 执行异常: %s" % (self.name, e))
            return True


class ExpeditionTask(Task):
    """远征: 领取已完成远征的奖励, 并重新派遣.

    注: 服务端把“已完成”状态混在初始推送的结构化数据里, 该层编码尚未解出,
        因此当前策略是「按配置的远征列表逐个领奖 + 重派」,
        并依赖状态码判定成败, 而不是先解析状态再决定。
        这也是保守间隔(默认 15 分钟)的原因之一。
    """

    name = "expedition"

    def __init__(self, ctx, expeditions=None, fleets=None):
        super().__init__(ctx)
        self.expeditions = expeditions or [10001]
        self.fleets = fleets or [6]

    def run(self):
        s = self.ctx.session
        s.verify_token()                     # ★ 动作前校验凭据
        all_ok = True
        for exp in self.expeditions:
            st = s.do_claim_expedition(exp)
            if st is None:
                all_ok = False
            for fleet in self.fleets:
                st2 = s.do_dispatch_expedition(fleet, exp)
                if st2 is None:
                    all_ok = False
        return all_ok


class DailySignTask(Task):
    """每日签到领奖 (msgid 7091).

    注意: 签到每天只能领一次, 服务端对重复领取的响应尚未实测标定,
          因此默认关闭, 需要时把 enabled 设为 True.
    """

    name = "daily_sign"
    interval = 6 * 3600

    def __init__(self, ctx, enabled=False, fields_hex=""):
        super().__init__(ctx)
        self.enabled = enabled
        self.fields_hex = fields_hex

    def should_run(self):
        return self.enabled

    def run(self):
        from . import proto
        s = self.ctx.session
        s.verify_token()
        fields = bytes.fromhex(self.fields_hex) if self.fields_hex else b""
        s.send(proto.build_message(proto.MSG_SIGN_REWARD, fields,
                                   trailer=len(fields) + 3 if fields else None))
        self.log("  [>] 每日签到领奖")
        time.sleep(0.8)
        frames, _ = s.recv_frames(2.5)
        for mid, ln, content in frames:
            self.log("  [<] msgid=%d (%d 字节)" % (mid, ln))
        return True


def default_tasks(ctx, cfg):
    """按配置组装任务列表."""
    tasks = []
    exp = cfg.get("expedition", {})
    if exp.get("enabled", True):
        t = ExpeditionTask(ctx, exp.get("ids", [10001]), exp.get("fleets", [6]))
        t.interval = exp.get("interval", 900)
        tasks.append(t)
    ds = cfg.get("daily_sign", {})
    t = DailySignTask(ctx, ds.get("enabled", False), ds.get("fields_hex", ""))
    t.interval = ds.get("interval", 6 * 3600)
    tasks.append(t)
    return tasks
