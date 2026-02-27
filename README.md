# 🔐 Web Crawling, Fuzzing & Sniffing Tool (ATTT Project)

## 📌 Giới thiệu
Đây là công cụ phục vụ môn **An Toàn Thông Tin (ATTT)**, được xây dựng với mục tiêu:
- Mô phỏng một số chức năng cơ bản của các công cụ kiểm thử bảo mật web như **Burp Suite** và **OWASP ZAP**
- Hỗ trợ **crawl website**, **fuzz tham số**, **bắt gói tin mạng**, và **demo một số lỗ hổng web**

Tool được phát triển bằng **Python**, kết hợp **PyQt5**, **async programming**, **Scapy** và **Web Engine**, hướng đến việc hiểu rõ cơ chế hoạt động của các kỹ thuật tấn công và phòng thủ trong ATTT.


## 🎯 Mục tiêu chính
- Crawl và thu thập các URL từ website mục tiêu
- Fuzz tham số URL bằng payload tấn công (XSS, SQL Injection, …)
- Phân tích phản hồi HTTP
- Bắt và phân tích traffic mạng ở mức packet
- Mô phỏng tấn công CSRF
- Cung cấp giao diện GUI trực quan cho người học ATTT


## 🛠 Công nghệ sử dụng
- **Python 3**
- **PyQt5** – xây dựng giao diện người dùng
- **qasync** – kết hợp asyncio với GUI
- **Scapy** – bắt và phân tích gói tin mạng
- **Requests / Selenium** – gửi HTTP request & crawl website
- **QWebEngineView** – hiển thị và tương tác với website


## 🧩 Cấu trúc project

├── app.py # File khởi chạy chính
├── webrawedit.py # Giao diện GUI chính (crawl, fuzz, web view)
├── fuzzcrawsniff.py # Logic crawl + fuzz + phân tích phản hồi
├── sniff.py # Bắt gói tin mạng bằng Scapy
├── CSRF.py # Mô phỏng / demo tấn công CSRF
├── payload.py # Danh sách payload tấn công (XSS, SQLi…)
├── index.html # Trang web demo/test
└── setup.py # Thông tin cấu hình / mô tả tool


## 🚀 Các chức năng chính

### 🔹 1. Web Crawling
- Thu thập các URL từ website mục tiêu
- Phục vụ cho quá trình fuzzing tự động

### 🔹 2. Fuzzing tham số
- Fuzz các tham số URL bằng payload tấn công
- Hỗ trợ kiểm tra các lỗ hổng phổ biến:
  - XSS (Cross-Site Scripting)
  - SQL Injection (cơ bản)

### 🔹 3. Phân tích phản hồi
- Quan sát HTTP response
- Hỗ trợ đánh giá hành vi ứng dụng khi nhận payload độc hại

### 🔹 4. Bắt gói tin mạng (Sniffing)
- Sử dụng Scapy để bắt các gói tin HTTP
- Phân tích traffic phục vụ học tập ATTT

### 🔹 5. Mô phỏng CSRF
- Demo nguyên lý tấn công CSRF
- Giúp hiểu tầm quan trọng của CSRF Token

### 🔹 6. Giao diện GUI
- Giao diện đồ họa thân thiện
- Không block khi crawl/fuzz nhờ async
- Tích hợp trình duyệt web bên trong tool


## ▶️ Cách chạy chương trình

### 1️⃣ Cài đặt thư viện cần thiết
pip install pyqt5 qasync scapy requests selenium
2️⃣ Chạy tool
python app.py
