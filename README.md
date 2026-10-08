# Minecraft Packet Attack Simulator

> **Công cụ mô phỏng tấn công packet Minecraft server — CHỈ dùng cho server CỦA BẠN.**

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()
[![Status](https://img.shields.io/badge/status-education%20%2F%20research-orange)]()

---

## ⚠️ CẢNH BÁO PHÁP LÝ

Đây là công cụ **stress test** dành cho **server Minecraft của chính bạn**, chạy trên:

- **Loopback** — `127.0.0.1`, `localhost`, `::1`
- **LAN private** — dải `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`

Mọi nỗ lực nhắm vào **IP public hoặc domain** sẽ bị **CHẶN tự động** ở tầng code.

> **Tấn công server KHÔNG thuộc quyền kiểm soát của bạn là hành vi VI PHẠM PHÁP LUẬT.**
>
> Tại Việt Nam: **Điều 289 Bộ luật Hình sự** — tội "Cản trở hoặc gây rối loạn hoạt động của mạng máy tính, mạng viễn thông" — khung hình phạt lên tới **12 năm tù**.
>
> Tác giả **không chịu trách nhiệm** về bất kỳ thiệt hại nào do sử dụng công cụ sai mục đích.

---

## 📖 Mục lục

- [Tổng quan](#-tổng-quan)
- [Tính năng](#-tính-năng)
- [Cấu trúc dự án](#-cấu-trúc-dự-án)
- [Yêu cầu](#-yêu-cầu)
- [Cài đặt](#-cài-đặt)
- [Bắt đầu nhanh](#-bắt-đầu-nhanh)
- [Danh sách attack](#-danh-sách-attack)
- [Hướng dẫn chi tiết](#-hướng-dẫn-chi-tiết)
- [Cấu hình server để test](#-cấu-hình-server-để-test)
- [Đo lường kết quả](#-đo-lường-kết-quả)
- [Xử lý sự cố](#-xử-lý-sự-cố)
- [Câu hỏi thường gặp](#-câu-hỏi-thường-gặp)
- [Giấy phép](#-giấy-phép)

---

## 🎯 Tổng quan

Bộ công cụ này mô phỏng các dạng tấn công packet tới **Minecraft Java Edition server** ở 3 tầng:

| Tầng | Mục tiêu | Đòn tiêu biểu |
|---|---|---|
| **Transport (L4)** | Backlog, accept queue, file descriptor | `conn`, `slow` |
| **Application (L7)** | Netty decoder, zlib, buffer allocation | `big`, `bomb`, `bigslow` |
| **Game logic** | Server thread (20 TPS), auth, chunk load | `play`, `chunk` |

Được viết **thuần Python**, không phụ thuộc thư viện ngoài, chạy được trên Windows / Linux / macOS.

---

## ✨ Tính năng

- ✅ **10 kịch bản attack** chia 3 nhóm rõ ràng
- ✅ **Full login flow** — hỗ trợ protocol 1.8 → 1.20.x
- ✅ **Login thật → spam PLAY packet** (đòn mạnh nhất, ăn vào Server thread)
- ✅ **Chunk-load DoS** — ép server load chunk liên tục
- ✅ **Compression bomb** — bandwidth thấp, RAM/CPU cao
- ✅ **Chẩn đoán login** (`debug_login.py`) — in từng packet nhận được
- ✅ **Whitelist an toàn** — chặn IP public / domain tự động
- ✅ **Self-test** cho từng module protocol
- ✅ **Không phụ thuộc thư viện ngoài** — chỉ Python standard library

---

## 📁 Cấu trúc dự án
