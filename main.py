#!/usr/bin/env python3
"""
================================================================================
 MINECRAFT PACKET ATTACK SIMULATOR  —  LOCAL / LAN ONLY
================================================================================

MỤC ĐÍCH
--------
Mô phỏng các dạng tấn công packet tới Minecraft server CỦA BẠN để:
    - Kiểm tra khả năng chịu tải (stress test).
    - Đo hiệu quả cấu hình phòng thủ (rate-limit, compression threshold).
    - Học về giao thức Minecraft ở tầng packet.

⚠️  CẢNH BÁO PHÁP LÝ
--------------------
Công cụ CHỈ cho phép target là:
    - Loopback      : 127.0.0.1, localhost, ::1
    - Private LAN   : 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16

Mọi nỗ lực nhắm vào IP public / domain sẽ bị CHẶN tự động.
Tấn công server KHÔNG thuộc quyền kiểm soát của bạn là VI PHẠM PHÁP LUẬT
(Luật An ninh mạng VN, Điều 289 Bộ luật Hình sự). Tác giả không chịu
trách nhiệm về việc sử dụng sai mục đích.

YÊU CẦU MÔI TRƯỜNG
------------------
    - Python 3.8+
    - Cùng thư mục với: attacks.py, mcproto.py, mcclient.py
    - Server Minecraft chạy chế độ offline-mode=false (cho attack play/chunk)

DANH SÁCH ATTACK
----------------
    Nhóm 1 — Connection / Handshake
        ping        Server List Ping flood
        login       Handshake + Login Start flood
        conn        TCP connection flood (chỉ mở socket)
        slow        Slowloris (gửi login từng byte)
        legacy      Legacy ping (0xFE 0x01)

    Nhóm 2 — Big Packet / Compression
        big         Gửi N packet 2MB / kết nối (pipelined)
        bomb        Compression bomb (bandwidth thấp, RAM cao)
        bigslow     Gửi packet lớn chia chunk nhỏ (giữ buffer)

    Nhóm 3 — Play State (mạnh nhất, ăn vào Server thread)
        play        Login thật → spam Chat / Position / Sign / Click
        chunk       Login → teleport liên tục → ép load chunk

CÁCH DÙNG NHANH
---------------
    # Xem help đầy đủ
    python main.py -h

    # Test nhẹ (không phá gì)
    python main.py --attack ping --workers 50 --duration 15 -y

    # Đòn mạnh nhất (cần debug_login.py chạy OK trước)
    python main.py --attack chunk --workers 20 --duration 60 --mcver 1.20 -y

    # Chạy combo
    python main.py --attack play  --workers 20 --duration 60 -y ^
    & python main.py --attack chunk --workers 20 --duration 60 -y

QUY TRÌNH ĐỀ XUẤT
-----------------
    1) Chạy `python debug_login.py` → xác nhận login OK.
    2) Chạy attack nhẹ (`ping`, `login`) để đo baseline.
    3) Chạy attack mạnh (`play`, `chunk`) để đo TPS impact.
    4) Mở PowerShell khác chạy `/spark tps` trên server.
    5) So sánh TPS trước / trong / sau attack.

ĐỌC KẾT QUẢ
-----------
    OK      : số packet / kết nối thành công
    Error   : số lần thất bại (timeout, refuse, reject)
    RPS     : requests/packet per second trung bình
    Bytes   : tổng dữ liệu đã gửi (attack big/bomb/bigslow)

    Nếu OK = 0 → server đang chặn / từ chối → chạy debug_login.py.
    Nếu OK > 0 nhưng TPS không giảm → attack nhắm sai tầng.

License : MIT — chỉ dùng cho server cá nhân.
================================================================================
"""

import argparse
import signal
import sys
import threading
import time
from datetime import datetime

from attacks import ATTACKS, ALLOWED_HOSTS, _check_host


# ============================================================
# BANNER
# ============================================================
BANNER = r"""
  __  __  ___   ___        _   _   _ _____ _   _
 |  \/  |/ __| / __| ___  | | | | / |_   _| | | |
 | |\/| | (__  \__ \/ _ \ | |_| |/ /  | | | |_| |
 |_|  |_|\___| |___/\___/ |  __/ /_/  |_|  \___/
                           |_|
     Minecraft Packet Attack Simulator  [LOCAL / LAN ONLY]
"""


# ============================================================
# PROTOCOL VERSION MAP
# ============================================================
PROTOCOL_VERSIONS = {
    "1.8":    47,
    "1.9":    107,
    "1.12":   335,
    "1.13":   393,
    "1.16":   754,
    "1.17":   755,
    "1.18":   757,
    "1.19":   760,
    "1.20":   763,
    "1.20.2": 764,
    "1.20.4": 765,
    "1.21":   767,
}


# ============================================================
# SAFETY
# ============================================================
def safety_check(host: str) -> bool:
    """Trả True nếu host nằm trong whitelist loopback / private LAN."""
    try:
        _check_host(host)
        return True
    except PermissionError as e:
        print(f"\n[✗] {e}\n")
        return False


# ============================================================
# STATS (dùng khi mở rộng — hiện chỉ heartbeat)
# ============================================================
class Stats:
    """Thu thập & in thống kê realtime (tuỳ chọn mở rộng)."""

    def __init__(self):
        self.start = time.time()
        self.last = self.start
        self.snapshots = []

    def snapshot(self, result: dict):
        now = time.time()
        dt = now - self.last
        self.last = now
        ok = result.get("ok", 0)
        err = result.get("err", 0)
        byt = result.get("bytes", 0)
        decomp = result.get("bytes_decompressed", 0)

        prev = self.snapshots[-1] if self.snapshots else {
            "ok": 0, "err": 0, "bytes": 0, "decomp": 0,
        }
        d_ok = ok - prev["ok"]
        d_err = err - prev["err"]
        d_byt = byt - prev["bytes"]
        d_decomp = decomp - prev["decomp"]

        self.snapshots.append({
            "ok": ok, "err": err, "bytes": byt, "decomp": decomp,
        })

        rps = d_ok / dt if dt > 0 else 0
        mbps = (d_byt * 8) / (dt * 1_000_000) if dt > 0 else 0

        line = (f"  [t={now - self.start:6.1f}s]  "
                f"OK={ok:<8} ERR={err:<6}  "
                f"ΔRPS={rps:7.1f}  ΔMbps={mbps:7.2f}")
        if d_decomp > 0:
            ratio = (d_decomp / d_byt) if d_byt > 0 else 0
            line += f"  decompress_ratio={ratio:6.1f}x"
        print(line)


# ============================================================
# ARGUMENT PARSER
# ============================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Mô phỏng tấn công packet tới Minecraft server LOCAL/LAN.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  # Nhóm 1 — connection / handshake
  python main.py --attack ping    --workers 50  --duration 15 -y
  python main.py --attack login   --workers 100 --duration 30 -y
  python main.py --attack conn    --workers 300 --duration 60 -y
  python main.py --attack slow    --workers 50  --duration 120 -y
  python main.py --attack legacy  --workers 50  --duration 30 -y

  # Nhóm 2 — big packet / compression
  python main.py --attack big     --workers 20 --duration 10 \\
                 --packet-size 2097152 --pipelined 10 -y
  python main.py --attack bomb    --workers 30 --duration 15 \\
                 --decompressed-size 2097152 -y
  python main.py --attack bigslow --workers 30 --duration 30 \\
                 --packet-size 2097152 -y

  # Nhóm 3 — play state (mạnh nhất, cần online-mode=false)
  python main.py --attack play    --workers 20 --duration 60 --mcver 1.20 -y
  python main.py --attack chunk   --workers 20 --duration 60 --mcver 1.20 -y
""",
    )

    # --- Target ---
    g = p.add_argument_group("Target (chỉ loopback / LAN private)")
    g.add_argument("--host", default="192.168.10.151",
                   help="Host (loopback hoặc IP private LAN)")
    g.add_argument("--port", type=int, default=58969,
                   help="Port server Minecraft")
    g.add_argument("--protocol", type=int, default=763,
                   help="Protocol version (763=1.20). Có thể dùng --mcver")
    g.add_argument("--mcver", choices=list(PROTOCOL_VERSIONS.keys()),
                   help="Tên phiên bản MC (override --protocol)")

    # --- Attack ---
    a = p.add_argument_group("Attack")
    a.add_argument("--attack", choices=sorted(ATTACKS.keys()),
                   default="ping", help="Kiểu tấn công")
    a.add_argument("--workers", type=int, default=100,
                   help="Số thread đồng thời")
    a.add_argument("--duration", type=int, default=30,
                   help="Thời gian chạy (giây)")

    # --- Big packet options ---
    b = p.add_argument_group(
        "Big-packet options (cho --attack big / bomb / bigslow)"
    )
    b.add_argument("--packet-size", type=int, default=2 * 1024 * 1024,
                   help="Kích thước packet tính bằng bytes (max 2MB)")
    b.add_argument("--decompressed-size", type=int, default=2 * 1024 * 1024,
                   help="Kích thước sau khi giải nén (cho --attack bomb)")
    b.add_argument("--mode", choices=["random", "zeros", "bomb", "mixed"],
                   default="random",
                   help="Kiểu dữ liệu (cho --attack big)")
    b.add_argument("--pipelined", type=int, default=10,
                   help="Số packet / kết nối (cho --attack big)")

    # --- Behaviour ---
    c = p.add_argument_group("Behaviour")
    c.add_argument("--yes", "-y", action="store_true",
                   help="Bỏ qua xác nhận")
    c.add_argument("--quiet", "-q", action="store_true",
                   help="Chỉ in kết quả cuối, không in heartbeat")
    c.add_argument("--stats-interval", type=float, default=1.0,
                   help="Chu kỳ in heartbeat (giây)")

    return p


# ============================================================
# BUILD KWARGS
# ============================================================
def build_kwargs(args) -> dict:
    """Map CLI args → kwargs cho từng hàm attack."""
    base = {"workers": args.workers, "duration": args.duration}
    attack = args.attack

    # Nhóm 1 + play + chunk: cần protocol
    if attack in ("ping", "login", "play", "chunk"):
        base["protocol"] = args.protocol

    # Nhóm 2
    elif attack == "big":
        base.update({
            "packet_size": args.packet_size,
            "mode": args.mode,
            "pipelined": args.pipelined,
            "protocol": args.protocol,
        })
    elif attack == "bomb":
        base.update({
            "decompressed_size": args.decompressed_size,
            "protocol": args.protocol,
        })
    elif attack == "bigslow":
        base.update({
            "packet_size": args.packet_size,
            "protocol": args.protocol,
        })

    # conn / slow / legacy: không cần thêm

    return base


# ============================================================
# PRINT CONFIG
# ============================================================
def print_config(args):
    print(BANNER)
    print("╔══════════════════════════════════════════════════════════╗")
    print(f"║  Target   : {args.host}:{args.port:<40}║")
    print(f"║  Attack   : {args.attack:<44}║")
    print(f"║  Workers  : {args.workers:<44}║")
    print(f"║  Duration : {args.duration:<43}s║")
    print(f"║  Protocol : {args.protocol:<44}║")

    if args.attack == "big":
        print(f"║  Pkt size : {args.packet_size:<37} bytes ║")
        print(f"║  Mode     : {args.mode:<44}║")
        print(f"║  Pipelined: {args.pipelined:<44}║")
    elif args.attack == "bomb":
        print(f"║  Decomp.  : {args.decompressed_size:<37} bytes ║")
    elif args.attack == "bigslow":
        print(f"║  Pkt size : {args.packet_size:<37} bytes ║")

    print("╚══════════════════════════════════════════════════════════╝\n")


# ============================================================
# PRINT RESULT
# ============================================================
def print_result(result: dict, elapsed: float):
    print("\n" + "═" * 62)
    print("  KẾT QUẢ")
    print("═" * 62)
    print(f"  Thời gian   : {elapsed:.2f}s")
    print(f"  OK          : {result.get('ok', 0):,}")
    print(f"  Error       : {result.get('err', 0):,}")

    if result.get("logins") is not None and result.get("logins", 0) > 0:
        print(f"  Logins      : {result['logins']:,}")

    if result.get("chunks_requested") is not None and result["chunks_requested"] > 0:
        print(f"  Chunks req. : {result['chunks_requested']:,}")

    if result.get("bytes"):
        total_bytes = result["bytes"]
        print(f"  Bytes sent  : {total_bytes:,} "
              f"({total_bytes / 1024 / 1024:.1f} MB)")
        if elapsed > 0:
            print(f"  Throughput  : "
                  f"{total_bytes / elapsed / 1024 / 1024:.2f} MB/s")

    if result.get("bytes_decompressed"):
        decomp = result["bytes_decompressed"]
        sent = result.get("bytes_sent", 1)
        print(f"  Decompressed: {decomp:,} bytes "
              f"(tỉ lệ nén ~{decomp / max(sent, 1):.0f}:1)")

    if elapsed > 0:
        print(f"  RPS         : {result.get('ok', 0) / elapsed:.1f} pkt/s")
    print("═" * 62)


# ============================================================
# SIGNAL HANDLING
# ============================================================
_STOP = {"flag": False}


def install_signal_handlers():
    def handler(signum, frame):
        if not _STOP["flag"]:
            print("\n[!] Nhận Ctrl+C — sẽ dừng sau khi workers kết thúc...")
            _STOP["flag"] = True

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)


# ============================================================
# HEARTBEAT THREAD
# ============================================================
def start_heartbeat(interval: float, quiet: bool):
    """In 'running...' mỗi interval giây. Trả về stop_event."""
    stop_stats = {"flag": False}

    def loop():
        t0 = time.time()
        while not stop_stats["flag"]:
            time.sleep(interval)
            if stop_stats["flag"]:
                break
            if not quiet:
                print(f"  [t={time.time() - t0:6.1f}s] running...")

    th = threading.Thread(target=loop, daemon=True)
    th.start()
    return stop_stats


# ============================================================
# POST-RUN HINTS
# ============================================================
def print_hints(host, port):
    """Gợi ý lệnh kiểm tra server — phân biệt Windows / Linux."""
    print("\n[i] Kiểm tra server (mở terminal KHÁC trên máy server):")
    print("")
    print("    Windows PowerShell:")
    print("        /spark tps                                  # trong game")
    print("        Get-Process java | Select WorkingSet       # RAM")
    print(f"        netstat -an | findstr :{port}                # kết nối")
    print("        Get-Content logs\\latest.log -Wait | Select-String "
          "-Pattern 'gc|oom|timeout|Can.t keep up'")
    print("")
    print("    Linux:")
    print("        ps -o rss= -p $(pgrep -f server.jar)        # RAM")
    print(f"        ss -tan state established '( sport = :{port} )' | wc -l")
    print("        tail -f logs/latest.log | "
          "grep -iE 'gc|oom|timeout|Can.t keep up'")
    print("")


# ============================================================
# MAIN
# ============================================================
def main():
    parser = build_parser()
    args = parser.parse_args()

    # --- Override protocol nếu user truyền --mcver ---
    if args.mcver:
        args.protocol = PROTOCOL_VERSIONS[args.mcver]

    # --- Safety ---
    if not safety_check(args.host):
        sys.exit(1)

    # --- In cấu hình ---
    print_config(args)

    # --- Xác nhận ---
    if not args.yes:
        try:
            ans = input("Bạn xác nhận đây là server CỦA BẠN (yes/no): ")
            ans = ans.strip().lower()
        except EOFError:
            ans = "no"
        if ans not in ("yes", "y"):
            print("Đã hủy.")
            sys.exit(0)

    # --- Signal ---
    install_signal_handlers()

    # --- Chuẩn bị ---
    fn = ATTACKS[args.attack]
    kwargs = build_kwargs(args)

    print(f"\n[+] Bắt đầu lúc {datetime.now().strftime('%H:%M:%S')}")
    print(f"[+] Attack: {args.attack} | Workers: {args.workers} "
          f"| Duration: {args.duration}s\n")

    # --- Heartbeat ---
    stop_stats = start_heartbeat(args.stats_interval, args.quiet)

    # --- Chạy attack ---
    t0 = time.time()
    try:
        result = fn(args.host, args.port, **kwargs)
    except KeyboardInterrupt:
        print("\n[!] Người dùng dừng.")
        stop_stats["flag"] = True
        sys.exit(130)
    except Exception as e:
        print(f"\n[✗] Lỗi khi chạy attack: {type(e).__name__}: {e}")
        stop_stats["flag"] = True
        sys.exit(1)

    elapsed = time.time() - t0
    stop_stats["flag"] = True

    # --- In kết quả ---
    print_result(result, elapsed)

    # --- Gợi ý ---
    print_hints(args.host, args.port)


if __name__ == "__main__":
    main()