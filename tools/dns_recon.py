# -*- coding: utf-8 -*-
"""DNS 侦察: 判断泛解析 + 爆破当前舰R API 入口域名."""
import socket
import sys
import concurrent.futures

RESOLVER = "223.5.5.5"


def resolve(name):
    try:
        return name, socket.gethostbyname(name)
    except Exception:
        return name, None


WORDS = [
    "login", "version", "passport", "sdk", "api", "hm", "user", "game", "gate",
    "srv", "server", "pay", "notice", "news", "cdn", "static", "dynamic",
    "xrcdn", "xrcdn2", "xrcdn3", "xrcdn4", "jr", "ios", "android", "app",
    "www", "m", "wap", "admin", "open", "id", "account", "auth", "oauth",
    "res", "resource", "download", "dl", "up", "update", "patch", "client",
    "web", "h5", "bbs", "forum", "wiki", "help", "cs", "service", "test",
    "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10",
    "s11", "s12", "s13", "s14", "s15", "s20", "s21", "s30", "s50", "s100",
]

ZONES = [
    "jr.moefantasy.com",
    "jianniang.com",
    "moefantasy.com",
    "jr.jianniang.com",
]

WILDCARD_PROBES = [
    "zzz-no-such-host-91827364",
    "qwertyuiop-abcdefg-112233",
]


def main():
    print("### 泛解析检测 ###")
    for zone in ZONES:
        hits = []
        for probe in WILDCARD_PROBES:
            n, ip = resolve(probe + "." + zone)
            hits.append(ip)
        verdict = "有泛解析(解析结果不可信)" if any(hits) else "无泛解析"
        print("  %-24s %s   probes=%s" % (zone, verdict, hits))

    print("\n### 子域爆破 ###")
    targets = []
    for zone in ZONES:
        for w in WORDS:
            targets.append(w + "." + zone)

    found = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
        for name, ip in ex.map(resolve, targets):
            if ip:
                found[name] = ip
    for name in sorted(found):
        print("  OK  %-34s %s" % (name, found[name]))
    print("  命中 %d / %d" % (len(found), len(targets)))


if __name__ == "__main__":
    main()
