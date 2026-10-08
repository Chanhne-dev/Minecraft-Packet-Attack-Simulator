#!/usr/bin/env python3
"""
================================================================================
 DEBUG LOGIN — Chẩn đoán kết nối Minecraft Server
================================================================================

MỤC ĐÍCH
--------
Kết nối tới server Minecraft (offline-mode) và in RA TỪNG PACKET nhận được.
Dùng để tìm ra lý do client không login được (khi attack báo OK=0).

CHẠY NHƯ THẾ NÀO
----------------
    1) Sửa HOST/PORT/PROTOCOL bên dưới cho khớp server của bạn.
    2) Mở PowerShell / cmd trong thư mục chứa file này.
    3) Chạy:
           python debug_login.py

ĐỌC KẾT QUẢ
-----------
    [→]  : packet ta GỬI đi
    [←]  : packet ta NHẬN về
    [✗]  : lỗi (socket đóng, timeout, parse lỗi)
    [*]  : ghi chú

    Các packet_id quan trọng ở LOGIN state:
        0x00 = Login Disconnect   → server TỪ CHỐI, xem "reason JSON"
        0x02 = Login Success      → server CHẤP NHẬN ✅
        0x03 = Set Compression    → bật nén, các packet sau phải zlib
        0x04 = Login Plugin Req   → server hỏi plugin, ta trả lời "không hiểu"
        0x05 = Login Plugin Resp  → server trả lời plugin request của ta

DIỄN GIẢI THƯỜNG GẶP
--------------------
    ""                             → Không kết nối được TCP (firewall/port)
    "You are not whitelisted"      → server.properties: white-list=true
    "You are not authenticated"    → server.properties: online-mode=true
    "Server is full"               → max-players nhỏ hơn số bot
    "Outdated client/server"       → PROTOCOL không khớp version server
    "Invalid session"              → online-mode=true, cần Mojang auth
    "Read timed out"               → server quá tải, tăng timeout

SAU KHI FIX XONG
----------------
    Chạy attack thật:
        python main.py --attack play --host <IP> --port <PORT> -y
    Mong đợi:
        OK > 0, logins > 0

LƯU Ý
-----
    - Server phải có online-mode=false để test được không cần Mojang auth.
    - Script tự đóng kết nối khi xong, không cần Ctrl+C.

================================================================================
"""

import socket
import struct
import time
import zlib


# ============================================================
# CẤU HÌNH — SỬA Ở ĐÂY
# ============================================================
HOST = "192.168.10.151"
PORT = 58969
PROTOCOL = 763          # 763 = 1.20/1.20.1 | 765 = 1.20.4 | 767 = 1.21
USERNAME = "debug_acc"
TIMEOUT = 10            # giây, tăng nếu server đang lag


# ============================================================
# PACKET HELPERS
# ============================================================
def wv(n: int) -> bytes:
    """Encode VarInt."""
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def ws(s: str) -> bytes:
    """Encode String (VarInt length + UTF-8 bytes)."""
    d = s.encode("utf-8")
    return wv(len(d)) + d


def pkt(pid: int, data: bytes) -> bytes:
    """Đóng gói packet: [length][packet_id][data]."""
    body = wv(pid) + data
    return wv(len(body)) + body


def rv(sock) -> int:
    """Đọc VarInt từ socket."""
    num, shift = 0, 0
    while True:
        b = sock.recv(1)
        if not b:
            raise EOFError("socket closed while reading varint")
        byte = b[0]
        num |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return num
        shift += 7
        if shift > 35:
            raise ValueError(f"varint too long: {num}")


def rexact(sock, n: int) -> bytes:
    """Đọc đúng n byte từ socket."""
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise EOFError(f"closed after {len(buf)}/{n} bytes")
        buf += c
    return buf


def read_pkt(sock, comp: bool = False):
    """Đọc 1 packet, trả (packet_id, data). Hỗ trợ cả nén zlib."""
    ln = rv(sock)
    data = rexact(sock, ln)

    if comp:
        # [data_length varint][body]
        # data_length == 0  → body không nén
        # data_length  > 0  → body nén zlib
        i, dl, shift = 0, 0, 0
        while True:
            b = data[i]; i += 1
            dl |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        body = zlib.decompress(data[i:]) if dl > 0 else data[i:]
    else:
        body = data

    # Parse packet_id (VarInt) ở đầu body
    i, pid, shift = 0, 0, 0
    while True:
        b = body[i]; i += 1
        pid |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return pid, body[i:]


def hexdump(b: bytes, n: int = 80) -> str:
    """In hex gọn để debug."""
    return b[:n].hex() + ("..." if len(b) > n else "")


def read_varint_field(data: bytes, offset: int = 0):
    """Đọc 1 trường VarInt trong payload, trả (value, next_offset)."""
    value, shift, i = 0, 0, offset
    while True:
        b = data[i]; i += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, i
        shift += 7


def read_string_field(data: bytes, offset: int = 0):
    """Đọc 1 trường String trong payload, trả (text, next_offset)."""
    slen, i = read_varint_field(data, offset)
    text = data[i:i + slen].decode("utf-8", "replace")
    return text, i + slen


# ============================================================
# LOGIN FLOW
# ============================================================
def send_handshake(sock):
    """Handshake state=2 (Login)."""
    payload = (
        wv(PROTOCOL)
        + ws(HOST)
        + struct.pack(">H", PORT)
        + wv(2)
    )
    sock.sendall(pkt(0x00, payload))
    print("[→] Handshake sent (state=login)")


def send_login_start(sock):
    """Login Start."""
    sock.sendall(pkt(0x00, ws(USERNAME)))
    print(f"[→] Login Start (username={USERNAME})")


def handle_login_disconnect(data):
    """In reason JSON từ Login Disconnect packet."""
    print("     ⚠ LOGIN DISCONNECT!")
    try:
        reason, _ = read_string_field(data, 0)
        print(f"     reason JSON: {reason}")
    except Exception as e:
        print(f"     (không parse được reason: {e})")


def handle_set_compression(data):
    """Trả threshold từ Set Compression packet."""
    threshold, _ = read_varint_field(data, 0)
    print(f"     compression enabled, threshold={threshold}")
    return threshold


def handle_plugin_request(sock, data):
    """Trả lời Login Plugin Request bằng 'không hiểu'."""
    msg_id, _ = read_varint_field(data, 0)
    # response: [message_id varint][success bool=false]
    sock.sendall(pkt(0x02, wv(msg_id) + b"\x00"))
    print(f"     [→] Plugin Request response (id={msg_id}, understood=false)")


def dump_following_packets(sock, comp: bool, count: int = 3):
    """Đọc thử N packet sau Login Success."""
    print(f"[*] Đọc tiếp {count} packet...")
    for _ in range(count):
        try:
            pid2, d2 = read_pkt(sock, comp)
            print(f"[←] packet_id=0x{pid2:02X} len={len(d2)}")
        except Exception as e:
            print(f"[✗] {e}")
            return


# ============================================================
# MAIN
# ============================================================
def main():
    print(f"[*] Kết nối {HOST}:{PORT} protocol={PROTOCOL}")

    try:
        s = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
        s.settimeout(TIMEOUT)
    except Exception as e:
        print(f"[✗] Không kết nối được: {type(e).__name__}: {e}")
        return

    try:
        send_handshake(s)
        send_login_start(s)

        comp = False
        deadline = time.time() + 15

        while time.time() < deadline:
            try:
                pid, data = read_pkt(s, comp)
            except (EOFError, TimeoutError, socket.timeout) as e:
                print(f"[✗] {type(e).__name__}: {e}")
                break
            except Exception as e:
                print(f"[✗] read_pkt error: {type(e).__name__}: {e}")
                break

            print(f"[←] packet_id=0x{pid:02X} ({pid}) len(data)={len(data)}")
            print(f"     head: {hexdump(data)}")

            # 0x00 ở LOGIN state = Disconnect
            if pid == 0x00 and not comp:
                handle_login_disconnect(data)
                break

            # 0x03 = Set Compression
            if pid == 0x03 and not comp:
                handle_set_compression(data)
                comp = True
                continue

            # 0x02 = Login Success
            if pid == 0x02:
                print("     ✓ LOGIN SUCCESS — server chấp nhận!")
                dump_following_packets(s, comp, count=3)
                break

            # 0x04 = Login Plugin Request
            if pid == 0x04:
                handle_plugin_request(s, data)
                continue

    except KeyboardInterrupt:
        print("\n[!] Người dùng ngắt.")
    finally:
        try:
            s.close()
        except Exception:
            pass
        print("[*] Done")


if __name__ == "__main__":
    main()