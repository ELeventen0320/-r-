# -*- coding: utf-8 -*-
"""对侦察出的候选主机做 端口连通性 + HTTP/HTTPS 探活."""
import socket
import ssl
import sys
import concurrent.futures

UA = "Dalvik/2.1.0 (Linux; U; Android 5.1.1; oppo a53 Build/LYZ28N)"

HOSTS = [
    "s2.jr.moefantasy.com",
    "passport.moefantasy.com",
    "api.moefantasy.com",
    "pay.moefantasy.com",
    "www.moefantasy.com",
    "passport.jianniang.com",
    "dynamic.jianniang.com",
    "static.jianniang.com",
    "xrcdn3.moefantasy.com",
]

PATHS = ["/", "/index/getInitConfigs/", "/1.0/get/login/@self"]


def tcp(host, port, timeout=6):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception as e:
        return False


def http_get(host, path, use_tls=False, timeout=10):
    port = 443 if use_tls else 80
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except Exception as e:
        return None, "connect: %s" % e
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=host)
        req = (
            "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
            "Accept-Encoding: identity\r\nConnection: close\r\n\r\n"
        ) % (path, host, UA)
        raw.sendall(req.encode())
        buf = b""
        raw.settimeout(timeout)
        while len(buf) < 65536:
            try:
                chunk = raw.recv(8192)
            except Exception:
                break
            if not chunk:
                break
            buf += chunk
        return buf, None
    except Exception as e:
        return None, "io: %s" % e
    finally:
        try:
            raw.close()
        except Exception:
            pass


def check(host):
    lines = ["=" * 78, host]
    p80 = tcp(host, 80)
    p443 = tcp(host, 443)
    lines.append("  tcp 80=%s  443=%s" % ("OPEN" if p80 else "closed/timeout",
                                          "OPEN" if p443 else "closed/timeout"))
    for use_tls in ((False, True) if p80 else ()) or ((True,) if p443 else ()):
        for path in PATHS:
            body, err = http_get(host, path, use_tls)
            proto = "https" if use_tls else "http"
            if err:
                lines.append("  %-5s %-24s ERR %s" % (proto, path, err))
                continue
            head = body.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
            status = head.split("\r\n")[0]
            rest = body.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in body else b""
            snippet = rest[:200].decode("utf-8", "replace").replace("\n", " ")
            lines.append("  %-5s %-24s %s | %d bytes | %s" % (proto, path, status, len(rest), snippet))
    return "\n".join(lines)


def main():
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        for out in ex.map(check, HOSTS):
            print(out)


if __name__ == "__main__":
    main()
