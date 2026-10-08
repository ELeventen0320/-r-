# -*- coding: utf-8 -*-
"""
RemoteZip: 通过 HTTP Range 请求读取远程 ZIP/APK, 无需完整下载.
仅依赖 Python 标准库.

用法:
    python remotezip.py list  <url> [outfile]
    python remotezip.py find  <url> <substr> [...]
    python remotezip.py pull  <url> <entryname> <localpath>
"""
import os
import struct
import sys
import time
import urllib.request
import urllib.error
import zlib

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_cache")
CHUNK = 4 * 1024 * 1024


def _cache_path(url):
    import hashlib
    return os.path.join(CACHE_DIR, hashlib.md5(url.encode()).hexdigest() + ".bin")


def range_get(url, start, end, retries=5):
    """闭区间 [start, end]."""
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": UA,
                "Range": "bytes=%d-%d" % (start, end),
                "Accept-Encoding": "identity",
            })
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read()
            if len(data) != (end - start + 1) and r.status != 206:
                raise IOError("short read %d != %d" % (len(data), end - start + 1))
            return data
        except Exception as e:
            last = e
            time.sleep(1.5 * (i + 1))
    raise IOError("range_get failed %d-%d: %s" % (start, end, last))


class RemoteZip(object):
    def __init__(self, url, size=None):
        self.url = url
        if size is None:
            req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=60) as r:
                size = int(r.headers["Content-Length"])
        self.size = size
        self.entries = {}
        self._read_eocd()
        self._read_central_directory()

    # ---------- EOCD ----------
    def _read_eocd(self):
        tail_len = min(self.size, 128 * 1024)
        tail_start = self.size - tail_len
        tail = range_get(self.url, tail_start, self.size - 1)

        idx = tail.rfind(b"PK\x05\x06")
        if idx < 0:
            raise IOError("EOCD not found")
        (sig, disk, cd_disk, n_disk, n_total, cd_size, cd_off, cmt_len) = struct.unpack_from(
            "<IHHHHIIH", tail, idx)

        self.cd_off = cd_off
        self.cd_size = cd_size
        self.n_total = n_total

        # ZIP64
        loc = tail.rfind(b"PK\x06\x07")
        if loc >= 0 and (cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF or n_total == 0xFFFF):
            (z64_off,) = struct.unpack_from("<Q", tail, loc + 8)
            z64 = range_get(self.url, z64_off, z64_off + 55)
            if z64[:4] != b"PK\x06\x06":
                raise IOError("bad zip64 EOCD")
            (_, _, _, _, n_disk, n_total, cd_size, cd_off) = struct.unpack_from("<IQHHIIQQ", z64, 0)
            self.cd_off = cd_off
            self.cd_size = cd_size
            self.n_total = n_total

    # ---------- central directory ----------
    def _read_central_directory(self):
        buf = bytearray()
        pos = self.cd_off
        remaining = self.cd_size
        while remaining > 0:
            n = min(CHUNK, remaining)
            buf += range_get(self.url, pos, pos + n - 1)
            pos += n
            remaining -= n

        off = 0
        while off + 46 <= len(buf):
            if buf[off:off + 4] != b"PK\x01\x02":
                break
            (_, ver_made, ver_need, flags, method, mtime, mdate, crc, csize, usize,
             fnlen, extralen, cmtlen, disk_start, iattr, eattr, lho) = struct.unpack_from(
                "<IHHHHHHIIIHHHHHII", buf, off)
            name = bytes(buf[off + 46:off + 46 + fnlen]).decode("utf-8", "replace")
            extra = bytes(buf[off + 46 + fnlen:off + 46 + fnlen + extralen])

            # ZIP64 extended info
            if 0xFFFFFFFF in (csize, usize, lho):
                p = 0
                while p + 4 <= len(extra):
                    hid, hsz = struct.unpack_from("<HH", extra, p)
                    if hid == 0x0001:
                        q = p + 4
                        if usize == 0xFFFFFFFF:
                            usize = struct.unpack_from("<Q", extra, q)[0]; q += 8
                        if csize == 0xFFFFFFFF:
                            csize = struct.unpack_from("<Q", extra, q)[0]; q += 8
                        if lho == 0xFFFFFFFF:
                            lho = struct.unpack_from("<Q", extra, q)[0]; q += 8
                        break
                    p += 4 + hsz

            self.entries[name] = {
                "method": method, "csize": csize, "usize": usize,
                "lho": lho, "flags": flags, "crc": crc,
            }
            off += 46 + fnlen + extralen + cmtlen

    # ---------- read one entry ----------
    def read(self, name):
        e = self.entries[name]
        head = range_get(self.url, e["lho"], e["lho"] + 29)
        if head[:4] != b"PK\x03\x04":
            raise IOError("bad local header for %s" % name)
        (_, _, _, method, _, _, _, _, _, fnlen, extralen) = struct.unpack_from("<IHHHHHIIIHH", head, 0)
        data_off = e["lho"] + 30 + fnlen + extralen
        if e["csize"] == 0 and e["usize"] == 0:
            return b""
        raw = bytearray()
        pos = data_off
        remaining = e["csize"]
        while remaining > 0:
            n = min(CHUNK, remaining)
            raw += range_get(self.url, pos, pos + n - 1)
            pos += n
            remaining -= n
        if method == 0:
            return bytes(raw)
        if method == 8:
            return zlib.decompress(bytes(raw), -15)
        raise IOError("unsupported method %d for %s" % (method, name))


def main():
    os.makedirs(CACHE_DIR, exist_ok=True)
    cmd = sys.argv[1]
    url = sys.argv[2]
    rz = RemoteZip(url)
    print("# entries=%d  cd_off=%d  cd_size=%d  zip_size=%d" % (
        len(rz.entries), rz.cd_off, rz.cd_size, rz.size))

    if cmd == "list":
        out = sys.argv[3] if len(sys.argv) > 3 else None
        lines = []
        for name in sorted(rz.entries):
            e = rz.entries[name]
            lines.append("%12d %12d  %s" % (e["usize"], e["csize"], name))
        text = "\n".join(lines)
        if out:
            with open(out, "w", encoding="utf-8") as f:
                f.write(text + "\n")
            print("written %s (%d entries)" % (out, len(lines)))
        else:
            print(text)
    elif cmd == "find":
        for kw in sys.argv[3:]:
            print("### %s" % kw)
            for name in sorted(rz.entries):
                if kw.lower() in name.lower():
                    print("  %12d  %s" % (rz.entries[name]["usize"], name))
    elif cmd == "pull":
        name, dest = sys.argv[3], sys.argv[4]
        data = rz.read(name)
        with open(dest, "wb") as f:
            f.write(data)
        print("pulled %s -> %s (%d bytes)" % (name, dest, len(data)))
    elif cmd == "head":
        # 只取条目前 n 字节(仅对 stored 未压缩条目精确)
        name = sys.argv[3]
        n = int(sys.argv[4]) if len(sys.argv) > 4 else 4096
        e = rz.entries[name]
        head = range_get(rz.url, e["lho"], e["lho"] + 29)
        (_, _, _, method, _, _, _, _, _, fnlen, extralen) = struct.unpack_from("<IHHHHHIIIHH", head, 0)
        data_off = e["lho"] + 30 + fnlen + extralen
        take = min(n, e["csize"])
        blob = range_get(rz.url, data_off, data_off + take - 1)
        print("# %s method=%d csize=%d usize=%d 取前 %d 字节" % (name, method, e["csize"], e["usize"], take))
        print("hex: %s" % blob[:64].hex(" "))
        print("asc: %s" % "".join(chr(c) if 32 <= c < 127 else "." for c in blob[:64]))
        try:
            txt = blob.decode("utf-8")
            print("---- utf8 ----")
            print(txt[:2000])
        except Exception as ex:
            print("(非 utf8: %s)" % ex)


if __name__ == "__main__":
    main()
