#!/usr/bin/env python3
"""
================================================================================
 MCPROTO — Minecraft Java Edition Protocol Packet Builder
================================================================================

MỤC ĐÍCH
--------

Được dùng bởi:
    - `mcclient.py` (login flow + PLAY packet builder)
    - `attacks.py`  (các kịch bản mô phỏng tấn công)
    - `debug_login.py` (chẩn đoán login)

CẤU TRÚC PACKET MINECRAFT
-------------------------
    Không nén:    [length: VarInt][packet_id: VarInt][data...]
    Có nén:       [length: VarInt][data_length: VarInt][body]
                  - data_length = 0   → body là [packet_id][data] KHÔNG nén
                  - data_length  > 0  → body là zlib([packet_id][data])

    Trong đó:
        length       = tổng số byte của các trường sau nó (không tính chính nó)
        packet_id    = định danh loại packet (theo state + direction)
        data_length  = kích thước TRƯỚC khi nén của [packet_id + data]

    VarInt tối đa 5 byte, biểu diễn signed 32-bit.

BẢNG VARINT (VÍ DỤ)
-------------------
    0        → 00
    127      → 7f
    128      → 80 01
    255      → ff 01
    2097151  → ff ff 7f          (2^21 - 1, giới hạn packet length vanilla)
    2147483647 → ff ff ff ff 07  (2^31 - 1, giới hạn VarInt)

API CHÍNH
---------
    Ghi:
        write_varint(v)                 → bytes
        write_string(s)                 → bytes  (VarInt length + UTF-8)
        write_ushort(v)                 → bytes  (big-endian 2 byte)
        write_long(v)                   → bytes  (big-endian 8 byte)

    Đóng gói:
        pack_packet(pid, payload)                       → không nén
        pack_packet_compressed(pid, payload, threshold) → có nén

    Packet cụ thể:
        make_handshake(host, port, state, protocol)
        make_login_start(username)
        make_status_request()

    Legacy (1.6 trở xuống):
        make_legacy_ping(host, port)

    Tấn công (stress test):
        make_big_login_plugin_response(size, packet_id)
        make_compression_bomb(uncompressed_size)
        make_rand_bytes_packet(size)

GIỚI HẠN CỦA PROTOCOL
---------------------
    - Packet length tối đa: 2^21 = 2,097,152 byte (2MB). Vượt → server ngắt.
    - String tối đa: 32767 ký tự.
    - VarInt không được vượt 5 byte.

LƯU Ý VỀ COMPRESSION BOMB
-------------------------
    `make_compression_bomb()` tạo packet có:
        - kích thước wire ~ vài KB (do zlib nén cao)
        - kích thước sau giải nén ~ 2MB
    Server phải `inflate()` để đọc → tốn CPU + cấp phát RAM.
    NHƯNG: với server vanilla, packet bị decode reject trước khi vào game
    logic → ảnh hưởng nằm ở Netty, KHÔNG vào Server thread → không giảm TPS.
    Chỉ dùng để test khả năng chịu tải của tầng transport.

LICENSE
-------
    MIT — chỉ dùng cho server cá nhân / LAN private.
================================================================================
"""

import os
import struct
import zlib


# ============================================================
# HẰNG SỐ
# ============================================================
MAX_PACKET_SIZE = 2 * 1024 * 1024    # 2MB — giới hạn packet length vanilla
MAX_STRING_LEN = 32767               # ký tự


# ============================================================
# WRITE HELPERS — VarInt / String / số cơ bản
# ============================================================
def write_varint(value: int) -> bytes:
    """Encode VarInt theo chuẩn Minecraft protocol."""
    out = b""
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def write_string(s: str) -> bytes:
    """Encode String (VarInt length + UTF-8)."""
    data = s.encode("utf-8")
    return write_varint(len(data)) + data


def write_ushort(v: int) -> bytes:
    """Encode unsigned short (big-endian 2 byte)."""
    return struct.pack(">H", v)


def write_long(v: int) -> bytes:
    """Encode signed long (big-endian 8 byte)."""
    return struct.pack(">q", v)


# ============================================================
# ĐÓNG GÓI PACKET
# ============================================================
def pack_packet(packet_id: int, payload: bytes) -> bytes:
    """
    Đóng gói packet KHÔNG nén.
    Format: [length][packet_id][payload]
    """
    body = write_varint(packet_id) + payload
    return write_varint(len(body)) + body


def compress_zlib(data: bytes, level: int = 9) -> bytes:
    """Nén zlib với level cho trước (9 = cao nhất)."""
    return zlib.compress(data, level)


def pack_packet_compressed(packet_id: int, payload: bytes,
                           threshold: int = 256,
                           compress_level: int = 9) -> bytes:
    """
    Đóng gói packet CÓ nén (dùng sau khi server gửi Set Compression).
    Format: [length][data_length][body]
        - Nếu body ≥ threshold: nén zlib, data_length = kích thước gốc
        - Ngược lại:            không nén,  data_length = 0
    """
    body = write_varint(packet_id) + payload
    if len(body) >= threshold:
        comp = compress_zlib(body, compress_level)
        inner = write_varint(len(body)) + comp       # data_length = gốc
    else:
        inner = write_varint(0) + body               # 0 = không nén
    return write_varint(len(inner)) + inner


# ============================================================
# PACKET CỤ THỂ — HANDSHAKE / LOGIN / STATUS
# ============================================================
def make_handshake(host: str, port: int, state: int = 2,
                   protocol: int = 763) -> bytes:
    """
    Handshake packet.
    state = 1 → STATUS (server list ping)
    state = 2 → LOGIN
    """
    payload = (
        write_varint(protocol)
        + write_string(host)
        + write_ushort(port)
        + write_varint(state)
    )
    return pack_packet(0x00, payload)


def make_login_start(username: str) -> bytes:
    """Login Start packet (state=LOGIN)."""
    payload = write_string(username)
    return pack_packet(0x00, payload)


def make_status_request() -> bytes:
    """Status Request (server list ping, state=STATUS)."""
    return pack_packet(0x00, b"")


# ============================================================
# LEGACY PROTOCOL (1.6 trở xuống)
# ============================================================
def make_legacy_ping(host: str, port: int) -> bytes:
    """
    Legacy Server List Ping (0xFE 0x01) — nhiều server hiện đại
    vẫn trả lời để tương thích ngược, dùng cho flood nhẹ.
    """
    payload = b"\xFE\x01\xFA" + write_string("MC|PingHost")
    payload += struct.pack(">H", 7 + 2 * len(host))   # độ dài phần còn lại
    payload += bytes([74])                            # protocol version cũ
    payload += write_string(host)
    payload += struct.pack(">I", port)
    return payload


# ============================================================
# STRESS TEST HELPERS
# ============================================================
def make_big_login_plugin_response(size: int = MAX_PACKET_SIZE,
                                   packet_id: int = 0x02) -> bytes:
    """
    Packet kích thước tuỳ ý với `packet_id` tuỳ ý, payload toàn 'A'.
    Dùng để test khả năng cấp phát buffer của server.
    """
    size = min(size, MAX_PACKET_SIZE)
    filler = b"A" * max(0, size - 1)
    return pack_packet(packet_id, filler)


def make_compression_bomb(uncompressed_size: int = MAX_PACKET_SIZE) -> bytes:
    """
    Packet có payload wire cực nhỏ nhưng giải nén ra ~2MB.
    Bandwidth thấp, nhưng ép server `inflate()` → tốn RAM/CPU.

    Lưu ý: server vanilla sẽ reject packet này ngay tại Netty decoder
    (unknown packet id / wrong state) → KHÔNG ảnh hưởng Server thread.
    """
    body = write_varint(0x00) + b"\x00" * uncompressed_size
    comp = zlib.compress(body, 9)
    inner = write_varint(len(body)) + comp       # data_length = kích thước gốc
    return write_varint(len(inner)) + inner


def make_rand_bytes_packet(size: int = MAX_PACKET_SIZE) -> bytes:
    """
    Packet chứa dữ liệu NGẪU NHIÊN — không nén được, tối đa bandwidth.
    Dùng để test throughput tầng transport.
    """
    size = min(size, MAX_PACKET_SIZE)
    return pack_packet(0x00, os.urandom(max(0, size - 1)))


# ============================================================
# SELF-TEST
# ============================================================
if __name__ == "__main__":
    # Kiểm tra VarInt encoding với vài giá trị biết trước
    cases = [
        (0,          b"\x00"),
        (1,          b"\x01"),
        (127,        b"\x7f"),
        (128,        b"\x80\x01"),
        (255,        b"\xff\x01"),
        (2097151,    b"\xff\xff\x7f"),
        (2147483647, b"\xff\xff\xff\xff\x07"),
    ]
    print("[*] Test VarInt encoding:")
    ok = 0
    for value, expected in cases:
        got = write_varint(value)
        mark = "✓" if got == expected else "✗"
        if got == expected:
            ok += 1
        print(f"  {mark} {value:>12}  →  {got.hex():<20} "
              f"(expected {expected.hex()})")
    print(f"    {ok}/{len(cases)} đúng\n")

    # Kiểm tra size của các helper
    print("[*] Test packet sizes:")
    hs = make_handshake("127.0.0.1", 25565)
    ls = make_login_start("Steve")
    sr = make_status_request()
    lp = make_legacy_ping("127.0.0.1", 25565)
    bb = make_big_login_plugin_response(1024)
    cb = make_compression_bomb(1024 * 1024)
    rb = make_rand_bytes_packet(1024)

    for name, pkt in [
        ("handshake",          hs),
        ("login_start",        ls),
        ("status_request",     sr),
        ("legacy_ping",        lp),
        ("big_plugin(1KB)",    bb),
        ("compression_bomb(1MB)", cb),
        ("rand_bytes(1KB)",    rb),
    ]:
        print(f"  {name:24} → {len(pkt):>10,} bytes")

    print("\n[*] Done")