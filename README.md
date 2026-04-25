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

### 1. Điều tra Domain / IP (đầy đủ nhất)
```bash
# Cơ bản (tự động chạy WHOIS + DNS + SSL + SPF/DMARC + subdomains + IP)
python osint.py domain example.com

# Đầy đủ bao gồm quét file nhạy cảm và cloud buckets
python osint.py domain example.com --secrets --cloud --report

# Tắt bớt module để chạy nhanh hơn
python osint.py domain example.com --no-subdomain --no-dorks --report --output ./reports
```

### 2. Phân tích SSL/TLS
```bash
python osint.py ssl example.com
python osint.py ssl example.com --port 8443 --report
```

### 3. Quét file nhạy cảm bị lộ
```bash
# Kiểm tra .git, .env, backup files, API keys, security.txt
python osint.py secrets example.com
python osint.py secrets https://example.com --report
```

### 4. Liệt kê Cloud Storage Buckets
```bash
python osint.py cloud example.com
python osint.py cloud mycompany --max-buckets 50 --report
```

### 5. Điều tra Email
```bash
python osint.py email user@example.com
python osint.py email user@example.com --hibp-key YOUR_KEY --report
# Hoặc đặt biến môi trường:
# set HIBP_API_KEY=your_key  (Windows)
# export HIBP_API_KEY=your_key  (Linux/Mac)
```

### 6. Kiểm tra Data Breach
```bash
python osint.py breach user@example.com
python osint.py breach user@example.com --password "mypassword"
python osint.py breach johndoe --report
```

### 7. Tìm Username trên 40+ nền tảng
```bash
python osint.py username johndoe
python osint.py username johndoe --report
```

### 8. Phân tích số điện thoại
```bash
python osint.py phone +84901234567
python osint.py phone 0901234567 --region VN --report
```

### 9. Điều tra Social Media (kèm Bot Detection)
```bash
python osint.py social --facebook johndoe
python osint.py social --tiktok johndoe --twitter johndoe --report
python osint.py social --reddit johndoe
```

### 10. Dorks cho cá nhân / tổ chức
```bash
python osint.py person "Nguyen Van A" --report
```

### 11. Full scan (tất cả modules + xuất báo cáo)
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
| `whois_lookup.py` | WHOIS + DNS + SPF/DKIM/DMARC + Zone Transfer + **DNSSEC/CAA/DANE analysis** | python-whois, dnspython |
| `ssl_analyzer.py` | SSL/TLS analysis — grade A+ đến F, cipher, cert, HSTS | ssl (built-in) |
| `secrets_scanner.py` | Exposed files scanner — .git, .env, backup, API keys + **Vulnerability Severity Scoring** | requests (free) |
| `cloud_recon.py` | Cloud bucket enum — AWS S3, GCS, Azure, DO Spaces | requests (free) |
| `email_recon.py` | Email recon, breach check, Gravatar | HIBP API, Gravatar |
| `username_search.py` | Username trên 40+ platform | Public profile URLs |
| `ip_lookup.py` | Geo, ASN, RDAP, Reverse IP, CVE table, HTTP headers + **Port Scanning + Advanced Security Headers Analysis** | ip-api.com (free), RDAP (free) |
| `phone_lookup.py` | Phân tích số điện thoại | phonenumbers (offline) |
| `google_dorks.py` | Google Dork queries | Tạo link tìm kiếm |
| `breach_check.py` | Breach check + severity scoring (CRITICAL/HIGH/MEDIUM/LOW) | LeakCheck, HIBP, BreachDirectory |
| `social_recon.py` | Social media recon + Bot/Fake account detection | Public APIs |
| `website_contacts.py` | Email, phone, social links từ website | RapidAPI |
| `youtube_recon.py` | YouTube channel OSINT | RapidAPI |
| `report.py` | Xuất báo cáo HTML + JSON | — |

---

## 🆕 Tính năng mới nâng cao (Security Research Focus)

### 🔍 Port Scanning & Service Detection
- Quét tự động 30+ cổng phổ biến (SSH, FTP, RDP, databases, etc.)
- Phát hiện dịch vụ đang chạy trên từng cổng
- Cảnh báo về các cổng nguy hiểm (Telnet, FTP, RDP, SMB, VNC)
- Banner grabbing để nhận dạng phiên bản dịch vụ

### 🛡️ Advanced Security Headers Analysis
- Phân tích chi tiết 7 security headers quan trọng
- Đánh giá từ A+ đến F với hướng dẫn khắc phục cụ thể
- Phát hiện cấu hình yếu trong HSTS, CSP, X-Frame-Options
- Gợi ý cấu hình header đúng chuẩn bảo mật

### 🔐 DNS Security Analysis (DNSSEC/CAA/DANE)
- Kiểm tra DNSSEC (DNS Security Extensions) để chống DNS spoofing
- Phân tích CAA records (Certificate Authority Authorization)
- Quét DANE/TLSA records cho TLS authentication
- Đánh giá DNS security score từ A đến F với khuyến nghị cải thiện

### 🚨 Vulnerability Severity Scoring
- Phân loại mức độ nguy hiểm: CRITICAL / HIGH / MEDIUM / LOW / INFO
- Tự động đánh giá severity cho từng file/path bị lộ
- Ưu tiên hiển thị các lỗ hổng nghiêm trọng (.git, .env, database dumps)
- Thống kê tổng hợp findings theo mức độ

---

## API Keys (Tùy chọn)

| Service | Link đăng ký | Dùng cho | Gói miễn phí |
|---------|-------------|----------|--------------|
| HaveIBeenPwned | https://haveibeenpwned.com/API/Key | Email breach check | $3.50/tháng |
| NumVerify | https://numverify.com | Phone validation | 100 req/tháng |
| Shodan | https://shodan.io | Open ports, CVEs | Free tier (100 req/tháng) |
| VirusTotal | https://virustotal.com | Malware/threat intel | 1000 req/ngày |
| AbuseIPDB | https://abuseipdb.com | IP abuse reputation | 1000 req/ngày |
| BreachDirectory | https://rapidapi.com/rohan-patra/api/breachdirectory | Breach database | 100 req/tháng |

---

## Cấu trúc thư mục

```
OSINT-Tool/
├── osint.py              # CLI chính
├── requirements.txt
├── README.md
└── modules/
    ├── ssl_analyzer.py       # ✨ MỚI: SSL/TLS analysis
    ├── secrets_scanner.py    # ✨ MỚI: Exposed files/secrets scanner
    ├── cloud_recon.py        # ✨ MỚI: Cloud bucket enumeration
    ├── whois_lookup.py       # ✨ MỞ RỘNG: + SPF/DKIM/DMARC + Zone Transfer
    ├── ip_lookup.py          # ✨ MỞ RỘNG: + RDAP + CVE severity table
    ├── breach_check.py       # ✨ MỞ RỘNG: + Breach severity scoring
    ├── social_recon.py       # ✨ MỞ RỘNG: + Bot/Fake account detection
    ├── email_recon.py
    ├── username_search.py
    ├── phone_lookup.py
    ├── google_dorks.py
    ├── website_contacts.py
    ├── youtube_recon.py
    └── report.py
```
