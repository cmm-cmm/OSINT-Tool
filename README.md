# OSINT Tool

Công cụ thu thập thông tin công khai (Open Source Intelligence) bằng Python, phục vụ mục đích nghiên cứu bảo mật và điều tra hợp pháp.

> ⚠ **Disclaimer**: Chỉ sử dụng dữ liệu công khai, hợp pháp. Người dùng chịu hoàn toàn trách nhiệm pháp lý.

---

## Cài đặt

```bash
pip install -r requirements.txt
```

---

## Sử dụng

### 1. Điều tra Domain / IP
```bash
python osint.py domain example.com
python osint.py domain 1.2.3.4 --report
python osint.py domain example.com --no-dorks --report --output ./reports
```

### 2. Điều tra Email
```bash
python osint.py email user@example.com
python osint.py email user@example.com --hibp-key YOUR_KEY --report
# Hoặc đặt biến môi trường:
# set HIBP_API_KEY=your_key  (Windows)
# export HIBP_API_KEY=your_key  (Linux/Mac)
```

### 3. Tìm Username trên 30+ nền tảng
```bash
python osint.py username johndoe
python osint.py username johndoe --report
```

### 4. Phân tích số điện thoại
```bash
python osint.py phone +84901234567
python osint.py phone 0901234567 --region VN --report
```

### 5. Dorks cho cá nhân / tổ chức
```bash
python osint.py person "Nguyen Van A" --report
```

### 6. Full scan (tất cả modules + xuất báo cáo)
```bash
python osint.py full example.com --type domain --output ./reports
python osint.py full user@example.com --type email --hibp-key KEY
python osint.py full johndoe --type username
python osint.py full +84901234567 --type phone
python osint.py full "Nguyen Van A" --type person
```

---

## Modules

| Module | Chức năng | Nguồn dữ liệu |
|--------|-----------|---------------|
| `whois_lookup.py` | WHOIS + DNS Enumeration | python-whois, dnspython |
| `email_recon.py` | Email recon, breach check, Gravatar | HIBP API (free key), Gravatar |
| `username_search.py` | Username trên 30+ platform | Public profile URLs |
| `ip_lookup.py` | Geo, ASN, Reverse IP, HTTP fingerprint | ip-api.com (free), HackerTarget |
| `phone_lookup.py` | Phân tích số điện thoại | phonenumbers (offline) |
| `google_dorks.py` | Google Dork queries | Tạo link tìm kiếm |
| `report.py` | Xuất báo cáo HTML + JSON | — |

---

## API Keys (Tùy chọn)

| Service | Link đăng ký | Dùng cho | Gói miễn phí |
|---------|-------------|----------|--------------|
| HaveIBeenPwned | https://haveibeenpwned.com/API/Key | Email breach check | $3.50/tháng |
| NumVerify | https://numverify.com | Phone validation | 100 req/tháng |

---

## Đánh giá nhanh & đề xuất cải tiến

Sau khi rà soát codebase hiện tại, đây là các cải tiến nên ưu tiên:

1. **Bổ sung test tự động cơ bản** cho các nhánh CLI quan trọng như `domain`, `email`, `phone` và `report` để tránh hồi quy.
2. **Chuẩn hóa HTTP client** dùng chung timeout, retry và xử lý lỗi thay vì để từng module tự gọi `requests.get(...)`.
3. **Tách nhỏ `modules/report.py` và `modules/social_recon.py`** vì đây là hai file lớn, đang ôm nhiều trách nhiệm nên khó bảo trì.
4. **Bổ sung logging mức debug** cho các API/public source bị lỗi để người dùng hiểu vì sao dữ liệu thiếu hoặc trả về `"N/A"`.
5. **Thêm cache/rate-limit** cho các nguồn public như `ip-api`, `crt.sh` hoặc endpoint tra cứu profile để giảm timeout và giới hạn truy cập.

### Cải tiến đã áp dụng trong lần rà soát này

- Siết chặt kiểm tra IPv4 trong CLI: tool không còn chấp nhận các địa chỉ không hợp lệ như `999.999.999.999`.

---

## Cấu trúc thư mục

```
OSINT-Tool/
├── osint.py              # CLI chính
├── requirements.txt
├── README.md
└── modules/
    ├── breach_check.py
    ├── whois_lookup.py
    ├── email_recon.py
    ├── username_search.py
    ├── ip_lookup.py
    ├── phone_lookup.py
    ├── google_dorks.py
    ├── social_recon.py
    ├── website_contacts.py
    ├── youtube_recon.py
    └── report.py
```
