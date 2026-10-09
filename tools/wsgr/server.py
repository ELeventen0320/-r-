# -*- coding: utf-8 -*-
"""
wsgr.bootstrap 增补: 自动选服

发现 (实测):
  `/auth/` 响应里的 `server_list` **不是服务器列表, 而是
  {服务器ID: 最后登录时间戳} 的映射**。例如:

      {"2": 1768971521, "4": 1768971718,
       "14": 1791508817, "13": 1768971739}

  其中 14 的戳等于当前时间 ⇒ 账号当前所在服务器是 **14**,
  其余是历史登录记录。

  `/xrpc` 的 notice.server_list 才是真正的服务器清单 (含 ip/port)。

因此"该连哪台"应当由 **auth 的时间戳 + notice 的地址**共同决定,
而不是像早期版本那样硬编码 xr-server-2。
"""
import time


def last_played(auth_info):
    """返回 [(server_id, timestamp), ...] 按时间倒序."""
    sl = auth_info.get("server_list") or {}
    out = []
    if isinstance(sl, dict):
        for k, v in sl.items():
            try:
                out.append((int(k), int(v)))
            except (TypeError, ValueError):
                continue
    return sorted(out, key=lambda x: -x[1])


def active_server(auth_info, notice):
    """选出账号当前所在服务器.

    返回 dict(id, name, host, port, last_played) 或 None.
    """
    played = last_played(auth_info)
    if not played:
        return None
    sid, ts = played[0]
    for s in (notice.get("notice", {}).get("server_list") or []):
        if s.get("id") == sid:
            return {"id": sid, "name": s.get("name"), "host": s.get("ip"),
                    "port": s.get("port"), "last_played": ts,
                    "age_seconds": int(time.time()) - ts}
    return {"id": sid, "name": None, "host": None, "port": None,
            "last_played": ts, "age_seconds": int(time.time()) - ts}


def game_endpoint(notice, server_id, prefer_port=10010):
    """给定服务器 ID, 从 notice 里取游戏服地址.

    notice 里的 port 对同一主机可能有多个 (如 10009 / 10059),
    真正的游戏长连接端口实测为 10010, 因此默认用它。
    """
    for s in (notice.get("notice", {}).get("server_list") or []):
        if s.get("id") == server_id:
            return s.get("ip"), prefer_port
    return None, None
