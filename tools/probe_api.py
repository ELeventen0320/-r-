# -*- coding: utf-8 -*-
"""探测新版游戏服是否仍提供老式 HTTP API (护萌宝 4.5.0 那套路径)."""
import hashlib
import time
import zlib
import urllib.request
import urllib.error

KEY = "ade2688f1904e9fb8d2efdb61b5e398a"
UA = "Dalvik/2.1.0 (Linux; U; Android 5.1.1; oppo a53 Build/LYZ28N)"
HOSTS = [
    "http://xr-server-2.moefantasy.com",
    "http://xr-server-4.moefantasy.com",
]
PATHS = [
    "/",
    "/auth/",
    "/api/initGame?&crazy=0",
    "/index/login/<account_id>?",
    "/pve/getPveData/",
    "/boat/supplyBoats/[1]/0/0/",
    "/explore/getResult/1/",
    "/index/getInitConfigs/",
    "/index/checkVer/5.6.0/100016/2&version=5.6.0&channel=100016&market=2",
]


def end(key=KEY):
    t = int(round(time.time() * 1000))
    e = hashlib.md5((str(t) + key).encode()).hexdigest()
    return "&t=%d&e=%s&gz=1&market=2&channel=100016&version=5.6.0" % (t, e)


def req(url):
    r = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Encoding": "identity"})
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            body = resp.read()
            return resp.status, body
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return None, str(e).encode()


def show(status, body):
    txt = None
    if body[:2] == b"\x78\x9c" or body[:1] == b"\x78":
        try:
            txt = zlib.decompress(body).decode("utf-8", "replace")
        except Exception:
            pass
    if txt is None:
        txt = body.decode("utf-8", "replace")
    txt = txt.replace("\r", " ").replace("\n", " ")[:260]
    return "%s | %s" % (status, txt)


for h in HOSTS:
    print("=" * 90)
    print("HOST %s" % h)
    for p in PATHS:
        url = h + p
        if "?" in p or p.endswith("/"):
            url = h + p + ("" if p.endswith("?") else "") + (end() if "?" not in p else "")
        s, b = req(url)
        print("  %-62s -> %s" % (p[:62], show(s, b)))
    # 带签名的 initGame
    s, b = req(h + "/api/initGame?&crazy=0" + end())
    print("  %-62s -> %s" % ("/api/initGame + 老签名", show(s, b)))
