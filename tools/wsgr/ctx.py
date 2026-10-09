# -*- coding: utf-8 -*-
"""wsgr.ctx —— 运行上下文 (配置 / 日志 / 会话)."""
import json
import os
import sys
import time

SELF = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(SELF, ".."))
DEFAULT_CAPTURE = os.path.abspath(
    os.path.join(ROOT, "..", "capture", "f10010", "10.0.2.15_S_C_53568.bin"))


def load_config(path=None):
    path = path or os.path.join(ROOT, "config.json")
    if os.path.exists(path):
        cfg = json.load(open(path, encoding="utf-8"))
    else:
        cfg = {}
    cfg.setdefault("server", "xr-server-2.moefantasy.com")
    cfg.setdefault("port", 10010)
    cfg.setdefault("token_file", os.path.join(ROOT, "token.txt"))
    cfg.setdefault("login_frame", DEFAULT_CAPTURE)
    cfg.setdefault("tick", 1.0)
    cfg.setdefault("reconnect_delay", 30)
    cfg.setdefault("expedition", {})
    cfg["expedition"].setdefault("enabled", True)
    cfg["expedition"].setdefault("ids", [10001])
    cfg["expedition"].setdefault("fleets", [6])
    cfg["expedition"].setdefault("interval", 900)
    cfg.setdefault("daily_sign", {"enabled": False, "interval": 6 * 3600})
    return cfg


class Ctx:
    def __init__(self, cfg, verbose=True):
        self.cfg = cfg
        self.verbose = verbose
        self.session = None
        self._logfile = None

    def attach_logfile(self, path):
        self._logfile = open(path, "a", encoding="utf-8")

    def log(self, msg):
        line = "[%s] %s" % (time.strftime("%m-%d %H:%M:%S"), msg)
        if self.verbose:
            print(line, flush=True)
        if self._logfile:
            self._logfile.write(line + "\n")
            self._logfile.flush()

    def load_token(self):
        p = self.cfg["token_file"]
        return open(p).read().strip() if os.path.exists(p) else None

    def save_token(self, tok):
        with open(self.cfg["token_file"], "w", encoding="utf-8") as f:
            f.write(tok)
