# OSINT Tool

A Python-based open source intelligence toolkit for security research and lawful investigation.

> ⚠ **Disclaimer**: Use only public and legal data sources. The user is fully responsible for compliance with applicable laws.

---

## Installation

```bash
pip install -r requirements.txt
```

---

## Usage

### 1. Domain / IP investigation (most comprehensive)
```bash
# Basic scan (runs WHOIS + DNS + SSL + SPF/DMARC + subdomains + IP automatically)
python osint.py domain example.com

# Full scan including secrets and cloud buckets
python osint.py domain example.com --secrets --cloud --report

# Disable modules for faster execution
python osint.py domain example.com --no-subdomain --no-dorks --report --output ./reports
```

### 2. SSL/TLS analysis
```bash
python osint.py ssl example.com
python osint.py ssl example.com --port 8443 --report
```

### 3. Exposed secrets scan
```bash
# Check .git, .env, backup files, API keys, security.txt
python osint.py secrets example.com
python osint.py secrets https://example.com --report
```

### 4. Cloud storage bucket enumeration
```bash
python osint.py cloud example.com
python osint.py cloud mycompany --max-buckets 50 --report
```

### 5. Email investigation
```bash
python osint.py email user@example.com
python osint.py email user@example.com --hibp-key YOUR_KEY --report
# Or set environment variable:
# set HIBP_API_KEY=your_key  (Windows)
# export HIBP_API_KEY=your_key  (Linux/Mac)
```

### 6. Data breach check
```bash
python osint.py breach user@example.com
python osint.py breach user@example.com --password "mypassword"
python osint.py breach johndoe --report
```

### 7. Username search across 40+ platforms
```bash
python osint.py username johndoe
python osint.py username johndoe --report
```

### 8. Phone number analysis
```bash
python osint.py phone +84901234567
python osint.py phone 0901234567 --region VN --report
```

### 9. Social media investigation (with bot detection)
```bash
python osint.py social --facebook johndoe
python osint.py social --tiktok johndoe --twitter johndoe --report
python osint.py social --reddit johndoe
```

### 10. Dork queries for people and organizations
```bash
python osint.py person "Nguyen Van A" --report
```

### 11. Full scan (all modules + report export)
```bash
python osint.py full example.com --type domain --output ./reports
python osint.py full user@example.com --type email --hibp-key KEY
python osint.py full johndoe --type username
python osint.py full +84901234567 --type phone
python osint.py full "Nguyen Van A" --type person
```

---

## Modules

| Module | Function | Data sources |
|--------|----------|--------------|
| `whois_lookup.py` | WHOIS + DNS + SPF/DKIM/DMARC + Zone Transfer + **DNSSEC/CAA/DANE analysis** | python-whois, dnspython |
| `ssl_analyzer.py` | SSL/TLS analysis — grade A+ to F, ciphers, certificates, HSTS | ssl (built-in) |
| `secrets_scanner.py` | Exposed file scanner — .git, .env, backups, API keys + **Vulnerability Severity Scoring** | requests (free) |
| `cloud_recon.py` | Cloud bucket enumeration — AWS S3, GCS, Azure, DO Spaces | requests (free) |
| `email_recon.py` | Email recon, breach lookup, Gravatar | HIBP API, Gravatar |
| `username_search.py` | Username search across 40+ platforms | Public profile URLs |
| `ip_lookup.py` | Geo, ASN, RDAP, reverse IP, CVE table, HTTP headers + **Port Scanning + Security Headers Analysis** | ip-api.com (free), RDAP (free) |
| `phone_lookup.py` | Phone number analysis | phonenumbers (offline) |
| `google_dorks.py` | Google Dork queries | Search link generation |
| `breach_check.py` | Breach check + severity scoring (CRITICAL/HIGH/MEDIUM/LOW) | LeakCheck, HIBP, BreachDirectory |
| `social_recon.py` | Social media recon + bot/fake account detection | Public APIs |
| `website_contacts.py` | Website email, phone, social links extraction | RapidAPI |
| `youtube_recon.py` | YouTube channel OSINT | RapidAPI |
| `report.py` | Export reports to HTML + JSON | — |

---

## 🆕 Advanced Security Research Features

### 🔍 Port Scanning & Service Detection
- Automatically scans 30+ common ports (SSH, FTP, RDP, databases, etc.)
- Detects running services per port
- Flags dangerous ports (Telnet, FTP, RDP, SMB, VNC)
- Performs banner grabbing to identify service versions

### 🛡️ Advanced Security Headers Analysis
- Detailed analysis of 7 important security headers
- Grades from A+ to F with remediation guidance
- Detects weak HSTS, CSP, and X-Frame-Options configurations
- Recommends secure header settings

### 🔐 DNS Security Analysis (DNSSEC/CAA/DANE)
- Checks DNSSEC for protection against DNS spoofing
- Analyzes CAA records for Certificate Authority authorization
- Scans DANE/TLSA records for TLS authentication
- Scores DNS security from A to F with improvement suggestions

### 🚨 Vulnerability Severity Scoring
- Classifies findings as CRITICAL / HIGH / MEDIUM / LOW / INFO
- Automatically assesses severity for exposed files and paths
- Prioritizes critical leaks like .git, .env, and database dumps
- Summarizes findings by severity level

---

## Optional API Keys

| Service | Signup link | Used for | Free tier |
|---------|-------------|----------|----------|
| HaveIBeenPwned | https://haveibeenpwned.com/API/Key | Email breach checking | $3.50/month |
| NumVerify | https://numverify.com | Phone validation | 100 requests/month |
| Shodan | https://shodan.io | Open ports, CVEs | Free tier (100 requests/month) |
| VirusTotal | https://virustotal.com | Malware/threat intelligence | 1000 requests/day |
| AbuseIPDB | https://abuseipdb.com | IP abuse reputation | 1000 requests/day |
| BreachDirectory | https://rapidapi.com/rohan-patra/api/breachdirectory | Breach database | 100 requests/month |

---

## Project Structure

```
OSINT-Tool/
├── osint.py              # Main CLI
├── requirements.txt
├── README.md
└── modules/
    ├── ssl_analyzer.py       # ✨ NEW: SSL/TLS analysis
    ├── secrets_scanner.py    # ✨ NEW: Exposed files/secrets scanner
    ├── cloud_recon.py        # ✨ NEW: Cloud bucket enumeration
    ├── whois_lookup.py       # ✨ EXPANDED: + SPF/DKIM/DMARC + Zone Transfer
    ├── ip_lookup.py          # ✨ EXPANDED: + RDAP + CVE severity table
    ├── breach_check.py       # ✨ EXPANDED: + Breach severity scoring
    ├── social_recon.py       # ✨ EXPANDED: + Bot/Fake account detection
    ├── email_recon.py
    ├── username_search.py
    ├── phone_lookup.py
    ├── google_dorks.py
    ├── website_contacts.py
    ├── youtube_recon.py
    └── report.py
```
