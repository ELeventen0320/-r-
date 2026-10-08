# -*- coding: utf-8 -*-
"""
从 pcap 里重组 TCP 流, 输出双向内容 (HTTP 请求+响应、或原始二进制).
用于还原手游 API 的完整请求/应答.
"""
import collections
import struct
import sys


def read_pcap(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif data[:4] == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise IOError("not a classic pcap: %s" % data[:4].hex())
    (_, _, _, _, _, _, network) = struct.unpack_from(endian + "IHHiIII", data, 0)
    pkts = []
    off = 24
    while off + 16 <= len(data):
        ts, tus, incl, orig = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        pkts.append((ts + tus / 1e6, data[off:off + incl]))
        off += incl
    return network, pkts


def parse_eth(pkt, linktype):
    if linktype == 1 and len(pkt) >= 14:
        return struct.unpack_from("!H", pkt, 12)[0], pkt[14:]
    if linktype == 113 and len(pkt) >= 16:
        return struct.unpack_from("!H", pkt, 14)[0], pkt[16:]
    return None, None


def parse_ip(payload, etype):
    if etype == 0x0800 and len(payload) >= 20:
        ihl = (payload[0] & 0x0F) * 4
        return 4, payload[9], ".".join(map(str, payload[12:16])), ".".join(map(str, payload[16:20])), payload[ihl:]
    if etype == 0x86DD and len(payload) >= 40:
        return 6, payload[6], "v6", "v6", payload[40:]
    return None, None, None, None, None


def main():
    path = sys.argv[1]
    only_port = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] != "-" else None
    out_path = sys.argv[3] if len(sys.argv) > 3 else None
    out = open(out_path, "w", encoding="utf-8", errors="replace") if out_path else sys.stdout

    def P(*a):
        print(*a, file=out)

    linktype, pkts = read_pcap(path)
    pkts.sort(key=lambda x: x[0])

    flows = collections.defaultdict(lambda: {"a": [], "b": [], "first": None})
    for ts, pkt in pkts:
        etype, pl = parse_eth(pkt, linktype)
        if not pl:
            continue
        v, proto, src, dst, ip = parse_ip(pl, etype)
        if proto != 6 or not ip or len(ip) < 20:
            continue
        doff = (ip[12] >> 4) * 4
        sport, dport = struct.unpack_from("!HH", ip, 0)
        seq = struct.unpack_from("!I", ip, 4)[0]
        payload = ip[doff:]
        if not payload:
            continue
        if only_port and only_port not in (sport, dport):
            continue
        key = tuple(sorted([(src, sport), (dst, dport)]))
        side = "a" if (src, sport) == key[0] else "b"
        f = flows[key]
        if f["first"] is None:
            f["first"] = ts
        f[side].append((seq, payload))

    for key, f in sorted(flows.items(), key=lambda kv: kv[1]["first"] or 0):
        total = sum(len(p) for _, p in f["a"]) + sum(len(p) for _, p in f["b"])
        if total == 0:
            continue
        P("=" * 100)
        P("FLOW  %s:%d  <->  %s:%d     (%d bytes)" % (key[0][0], key[0][1], key[1][0], key[1][1], total))
        for side, label in (("a", ">>> A->B"), ("b", "<<< B->A")):
            chunks = sorted(f[side], key=lambda x: x[0])
            blob = b"".join(c[1] for c in chunks)
            if not blob:
                continue
            P("\n  --- %s (%d bytes) ---" % (label, len(blob)))
            text = blob.decode("utf-8", "replace")
            printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
            if printable / max(1, len(text)) > 0.85:
                body = text
                if len(body) > 4000:
                    body = body[:4000] + "\n...[截断 %d 字节]" % (len(text) - 4000)
                P(body)
            else:
                try:
                    import zlib
                    dec = zlib.decompress(blob)
                    P("[zlib OK %d -> %d]" % (len(blob), len(dec)))
                    P(dec.decode("utf-8", "replace")[:4000])
                except Exception:
                    P("[binary %d bytes] hex: %s" % (len(blob), blob[:200].hex(" ")))


if __name__ == "__main__":
    main()

