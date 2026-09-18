"""Build-specific, bounded helpers. No process writes or key persistence here."""
from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from wechat_ai_bot.services.core.linux_sqlcipher import verify_sqlcipher_page_hmac

BUILD_ID = "d16278a416e000526fd22aec59973e54f91291e4"
PROFILE = {
    "cipher": (0x89A6560, "55415741564155415453504d89ce4d89"),
    "kdf": (0x89A64D0, "55415741564155415453504489cb4d89"),
    "key": (0x89863B0, "4885ff74794885d2747485c974705541"),
    "caller": (0x89A452D, "ff50384883c41085c0488b542428747f"),
}
CIPHER_RETURN = 0x89A4530
PREFIX = "WECHAT_PROBE_EVENT "


class ProbeError(Exception):
    """Only constant, non-secret error messages may be used."""


def elf_info(path):
    with open(path, "rb") as f:
        h = f.read(64)
        if h[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", h, 18)[0] != 62:
            raise ProbeError("unsupported ELF architecture")
        offset = struct.unpack_from("<Q", h, 32)[0]
        size, count = struct.unpack_from("<HH", h, 54)
        segments, build_id = [], None
        for i in range(count):
            f.seek(offset + size * i)
            kind, flags, off, va, _, filesz, memsz, align = struct.unpack("<IIQQQQQQ", f.read(56))
            segments.append((kind, flags, off, va, filesz, memsz))
            if kind == 4:
                f.seek(off)
                notes = f.read(filesz)
                pos = 0
                while pos + 12 <= len(notes):
                    ns, ds, typ = struct.unpack_from("<III", notes, pos)
                    pos += 12
                    name = notes[pos:pos + ns].rstrip(b"\0")
                    pos += (ns + 3) & ~3
                    desc = notes[pos:pos + ds]
                    pos += (ds + 3) & ~3
                    if name == b"GNU" and typ == 3:
                        build_id = desc.hex()
        return build_id, segments


def file_offset(va, segments):
    for kind, flags, off, base, filesz, _ in segments:
        if kind == 1 and flags & 1 and base <= va < base + filesz:
            return off + va - base
    raise ProbeError("address is outside executable ELF segment")


def mappings(pid):
    rows = []
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        fields = line.split(None, 5)
        lo, hi = (int(x, 16) for x in fields[0].split("-"))
        rows.append((lo, hi, fields[1], int(fields[2], 16), fields[3], int(fields[4])))
    return rows


def resolve(pid, read_memory=None):
    exe = Path(f"/proc/{pid}/exe")
    build_id, segments = elf_info(exe)
    if build_id != BUILD_ID:
        raise ProbeError("unsupported Build ID; refusing old addresses")
    st = exe.stat()
    rows = mappings(pid)
    bases = set()
    for lo, hi, perms, off, dev, inode in rows:
        major, minor = (int(x, 16) for x in dev.split(":"))
        if inode != st.st_ino or (major, minor) != (os.major(st.st_dev), os.minor(st.st_dev)) or "x" not in perms:
            continue
        for kind, flags, poff, va, filesz, _ in segments:
            if kind == 1 and flags & 1 and poff // 4096 == off // 4096:
                bases.add(lo - (va + off - poff))
    if len(bases) != 1:
        raise ProbeError("ambiguous ELF load bias")
    base = bases.pop()
    owned = None
    if read_memory is None:
        owned = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
        read_memory = lambda addr, size: os.pread(owned, size, addr)
    try:
        with exe.open("rb") as f:
            for va, expected in PROFILE.values():
                expected = bytes.fromhex(expected)
                f.seek(file_offset(va, segments))
                if f.read(len(expected)) != expected:
                    raise ProbeError("ELF instruction signature mismatch")
                if not any(lo <= base + va and base + va + len(expected) <= hi and "x" in perms
                           for lo, hi, perms, *_ in rows):
                    raise ProbeError("breakpoint is not executable")
                if bytes(read_memory(base + va, len(expected))) != expected:
                    raise ProbeError("live instruction signature mismatch")
    finally:
        if owned is not None:
            os.close(owned)
    return base


def bounded_read(read_memory, address, length, maximum=4096):
    if address <= 0 or not 0 < length <= maximum:
        raise ProbeError("invalid buffer bounds")
    result = bytes(read_memory(address, length))
    if len(result) != length:
        raise ProbeError("short buffer read")
    return result


def tracer_pid(pid):
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("TracerPid:"):
                return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError):
        return None


def candidates(event):
    """Only material from observed calls; no format guessing or memory scans."""
    kind = event.get("kind")
    if kind == "cipher" and event.get("trusted_caller"):
        value = bytes.fromhex(event["buffer"])
        return [value] if len(value) == 32 else []
    if kind == "kdf_return" and event.get("success"):
        value = bytes.fromhex(event["buffer"])
        return [value] if len(value) == 32 else []
    return []
