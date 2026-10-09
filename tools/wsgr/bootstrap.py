# -*- coding: utf-8 -*-
"""
wsgr.bootstrap —— HTTP 引导链 (全部实测验证)

  1) POST http://xrpc.moefantasy.com/                     补丁 + 服务器列表 (zlib JSON)
  2) POST http://xr-server-4.moefantasy.com:10005/auth/   账号认证 (明文 JSON)
     (实测 10005 只在 xr-server-4 开放)
"""
import json
import urllib.parse
import urllib.request
import zlib

UA = "Dalvik/2.1.0 (Linux; U; Android 5.1.1; oppo a53 Build/LYZ28N)"
XRPC = "http://xrpc.moefantasy.com/"
AUTH_HOST = "xr-server-4.moefantasy.com"
AUTH_PORT = 10005
APP_VERSION = "v5.6.0"
APP_ID = "xr_cn_release"
CHANNEL = "taptap"


class AuthError(Exception):
    """认证失败 (token 失效等)."""

    def __init__(self, code, msg):
        super().__init__("认证失败 error_code=%s msg=%s" % (code, msg))
        self.code = code
        self.msg = msg


def _http(url, data=None, timeout=20):
    body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, headers={
        "User-Agent": UA,
        "Accept-Encoding": "identity",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def get_notice(patch_list=None, channel=CHANNEL):
    """补丁检查 + 服务器列表."""
    if patch_list is None:
        patch_list = {"data_hd": "0.0.178.1", "main": "0.0.629.1"}
    form = ("app_version=%s&app_id=%s&os_type=android&patch_list=%s&channel=%s") % (
        APP_VERSION, APP_ID,
        urllib.parse.quote(json.dumps(patch_list, separators=(",", ":"))),
        channel)
    st, raw = _http(XRPC, form)
    return json.loads(zlib.decompress(raw).decode())


def server_list(notice):
    """从公告里取服务器列表 [(id, name, host, port)]."""
    out = []
    for s in notice["notice"]["server_list"]:
        out.append((s["id"], s["name"], s["ip"], s["port"]))
    return out


def auth(token, host=AUTH_HOST, port=AUTH_PORT):
    """账号认证. 返回账号信息 dict; 失败抛 AuthError.

    ★ 每次动作前都应调用本函数校验, 因为 token 会失效;
      症状与"服务端限流"完全相同 (连接正常但动作被静默忽略), 极易误判.
    """
    body = json.dumps({"token": token, "channel": "hm_sdk_android"},
                      separators=(",", ":"))
    st, raw = _http("http://%s:%d/auth/" % (host, port), body)
    txt = raw.decode("utf-8", "replace")
    try:
        info = json.loads(txt)
    except Exception:
        raise AuthError(-1, "响应非 JSON: %s" % txt[:120])
    code = info.get("error_code", info.get("error", 0))
    if code:
        raise AuthError(code, info.get("error_msg", ""))
    return info


def check_token(token, **kw):
    """只校验 token, 返回 True/False (不抛异常)."""
    try:
        auth(token, **kw)
        return True
    except AuthError:
        return False
