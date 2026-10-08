# -*- coding: utf-8 -*-
"""
解析 tcpdump 抓包: 提取 DNS 查询、TLS SNI、HTTP 请求, 用于还原手游 API 端点.
纯标准库实现 (pcap + Ethernet/SLL + IPv4/IPv6 + TCP/UDP).
"""
import collections
import struct
import sys


def read_pcap(path):
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian = "<"   # pcapng
    else:
        raise IOError("unknown pcap magic %s" % magic.hex())
    if magic == b"\x4d\x3c\xb2\xa1":
        return None, "pcapng (需另处理)"
    (_, vmaj, vmin, tz, sig, snap, network) = struct.unpack_from(endian + "IHHiIII", data, 0)
    pkts = []
    off = 24
    while off + 16 <= len(data):
        ts, tus, incl, orig = struct.unpack_from(endian + "IIII", data, off)
        off += 16
        pkts.append((ts, data[off:off + incl]))
        off += incl
    return (network, pkts), None


def parse_eth(pkt, linktype):
    if linktype == 1:      # Ethernet
        if len(pkt) < 14:
            return None
        etype = struct.unpack_from("!H", pkt, 12)[0]
        return etype, pkt[14:]
    if linktype == 113:    # Linux SLL
        if len(pkt) < 16:
            return None
        etype = struct.unpack_from("!H", pkt, 14)[0]
        return etype, pkt[16:]
    if linktype in (105, 127):  # 802.11
        return None, None
    return None, None


def parse_ip(payload, etype):
    if etype == 0x0800 and len(payload) >= 20:
        ihl = (payload[0] & 0x0F) * 4
        proto = payload[9]
        src = ".".join(str(b) for b in payload[12:16])
        dst = ".".join(str(b) for b in payload[16:20])
        return 4, proto, src, dst, payload[ihl:]
    if etype == 0x86DD and len(payload) >= 40:
        proto = payload[6]
        src = ":".join("%02x%02x" % (payload[8 + i], payload[9 + i]) for i in range(0, 16, 2))
        dst = ":".join("%02x%02x" % (payload[22 + i], payload[23 + i]) for i in range(0, 16, 2))
        return 6, proto, src, dst, payload[40:]
    return None, None, None, None, None


def l4(proto, payload):
    if proto == 6 and len(payload) >= 20:      # TCP
        doff = (payload[12] >> 4) * 4
        sport, dport = struct.unpack_from("!HH", payload, 0)
        return sport, dport, payload[doff:]
    if proto == 17 and len(payload) >= 8:      # UDP
        sport, dport = struct.unpack_from("!HH", payload, 0)
        return sport, dport, payload[8:]
    return None, None, None


def dns_query(payload):
    """从 UDP/53 负载里取查询域名."""
    if len(payload) < 13:
        return None
    qdcount = struct.unpack_from("!H", payload, 4)[0]
    if qdcount < 1:
        return None
    i = 12
    labels = []
    while i < len(payload):
        ln = payload[i]
        if ln == 0:
            break
        if ln & 0xC0:
            break
        labels.append(payload[i + 1:i + 1 + ln].decode("latin-1"))
        i += 1 + ln
    name = ".".join(labels)
    return name or None


def tls_sni(payload):
    """从 TLS ClientHello 里取 SNI."""
    if len(payload) < 6 or payload[0] != 0x16:
        return None
    try:
        # TLS record: type(1) ver(2) len(2)
        rec_len = struct.unpack_from("!H", payload, 3)[0]
        hs = payload[5:5 + rec_len]
        if not hs or hs[0] != 0x01:      # ClientHello
            return None
        p = 4 + 2 + 32                   # type+len, version, random
        sid_len = hs[p]
        p += 1 + sid_len
        cs_len = struct.unpack_from("!H", hs, p)[0]
        p += 2 + cs_len
        comp_len = hs[p]
        p += 1 + comp_len
        ext_total = struct.unpack_from("!H", hs, p)[0]
        p += 2
        end = p + ext_total
        while p + 4 <= end and p + 4 <= len(hs):
            etype, elen = struct.unpack_from("!HH", hs, p)
            p += 4
            if etype == 0x0000:          # server_name
                # list_len(2) name_type(1) name_len(2) name
                nlen = struct.unpack_from("!H", hs, p + 3)[0]
                return hs[p + 5:p + 5 + nlen].decode("latin-1")
            p += elen
    except Exception:
        return None
    return None


def main():
    path = sys.argv[1]
    parsed, err = read_pcap(path)
    if err:
        print("ERR: %s" % err)
        return
    linktype, pkts = parsed
    print("# linktype=%d  packets=%d" % (linktype, len(pkts)))

    dns = collections.Counter()
    sni = collections.Counter()
    http_hosts = collections.Counter()
    http_reqs = []
    conns = collections.Counter()
    payloads = []

    for ts, pkt in pkts:
        etype, pl = parse_eth(pkt, linktype)
        if not pl:
            continue
        v, proto, src, dst, ip = parse_ip(pl, etype)
        if not ip:
            continue
        sport, dport, l4p = l4(proto, ip)
        if l4p is None:
            continue
        conns[(src, sport, dst, dport)] += 1

        if dport == 53 or sport == 53:
            q = dns_query(l4p)
            if q:
                dns[q] += 1
        if l4p[:1] == b"\x16":
            s = tls_sni(l4p)
            if s:
                sni[s] += 1
        if l4p[:4] in (b"GET ", b"POST", b"HEAD", b"PUT "):
            head = l4p.split(b"\r\n\r\n", 1)[0]
            first = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            host = ""
            for line in head.split(b"\r\n")[1:]:
                if line.lower().startswith(b"host:"):
                    host = line.split(b":", 1)[1].strip().decode("latin-1")
            http_hosts[host] += 1
            http_reqs.append((host, first))
            payloads.append(l4p)

    print("\n### DNS 查询域名 ###")
    for k, v in dns.most_common(60):
        print("  %4d  %s" % (v, k))

    print("\n### TLS SNI (HTTPS 域名) ###")
    for k, v in sni.most_common(60):
        print("  %4d  %s" % (v, k))

    print("\n### 明文 HTTP 请求 ###")
    for k, v in http_hosts.most_common(60):
        print("  %4d  %s" % (v, k))
    print("  --- 前 60 条请求行 ---")
    for host, first in http_reqs[:60]:
        print("    %-40s %s" % (host, first))

    print("\n### 连接数 Top 25 (src, sport, dst, dport) ###")
    for k, v in conns.most_common(25):
        print("  %5d  %s:%s -> %s:%s" % (v, k[0], k[1], k[2], k[3]))

    if payloads:
        with open(path + ".http.bin", "wb") as f:
            f.write(b"\n\n=====\n\n".join(payloads))
        print("\n明文 HTTP 负载已存: %s.http.bin" % path)


if __name__ == "__main__":
    main()
