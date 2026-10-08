# -*- coding: utf-8 -*-
"""重放捕获到的游戏服请求, 验证脱机连接可行性."""
import collections
import socket
import sys
import time

D = r"C:\Users\26912\Projects\wsgr-rt\capture\f10010"
HOST = "xr-server-2.moefantasy.com"
PORT = 10010


def load(name):
    with open(D + "\\" + name, "rb") as f:
        return f.read()


def hexdump(b, n=160):
    out = []
    for i in range(0, min(len(b), n), 16):
        chunk = b[i:i + 16]
        out.append("%04x  %-47s  %s" % (
            i,
            " ".join("%02x" % c for c in chunk),
            "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)))
    return "\n".join(out)


def main():
    req = load("10.0.2.15_S_C_53568.bin")   # 客户端 -> 服务端
    hello = load("10.0.2.15_S_C_40396.bin")
    print("客户端首包 (%d 字节):\n%s" % (len(hello), hexdump(hello)))
    print("\n客户端进入游戏请求 (%d 字节):\n%s" % (len(req), hexdump(req)))

    for label, payloads in (("先发 12 字节握手, 再发 362 字节请求", [hello, req]),
                            ("直接发 362 字节请求", [req])):
        print("\n" + "=" * 90)
        print("尝试: %s" % label)
        s = socket.socket()
        s.settimeout(12)
        try:
            s.connect((HOST, PORT))
            print("  已连接 %s:%d" % (HOST, PORT))
            for p in payloads:
                s.sendall(p)
                print("  发送 %d 字节" % len(p))
                time.sleep(0.6)
            total = b""
            deadline = time.time() + 8
            while time.time() < deadline:
                try:
                    chunk = s.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                total += chunk
                if len(total) > 200000:
                    break
            print("  收到 %d 字节" % len(total))
            if total:
                print(hexdump(total, 256))
        except Exception as e:
            print("  失败: %s" % e)
        finally:
            s.close()


if __name__ == "__main__":
    main()
