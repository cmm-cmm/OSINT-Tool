# OSINT Tool v1.2.0

A modular open-source intelligence toolkit.

## Modules

| # | Module | Tags | Optional deps |
|---|--------|------|--------------|
| 1 | 🌐 **Domain / IP Recon** | `domain`, `dns`, `whois`, `ssl`, `recon`, `subdomain` | — |
| 2 | 📧 **Email OSINT** | `email`, `breach`, `recon`, `osint` | `holehe` |
| 3 | 👤 **Username Search** | `username`, `social`, `osint`, `recon` | `maigret` |
| 4 | 📞 **Phone Lookup** | `phone`, `osint`, `recon` | — |
| 5 | 🌍 **IP Intelligence** | `ip`, `geo`, `shodan`, `recon` | — |
| 6 | 🔒 **SSL / TLS Analyzer** | `ssl`, `tls`, `certificate`, `security` | — |
| 7 | 📸 **Instagram OSINT** | `instagram`, `social`, `osint` | `instaloader` |
| 8 | 📱 **Social Media OSINT** | `social`, `facebook`, `tiktok`, `twitter`, `reddit`, `osint` | — |
| 9 | 💥 **Breach Check** | `breach`, `email`, `password`, `osint` | — |
| 10 | 🔑 **Secrets Scanner** | `secrets`, `exposure`, `security`, `recon` | — |
| 11 | ☁️ **Cloud Bucket Recon** | `cloud`, `s3`, `gcs`, `azure`, `recon` | — |
| 12 | 📜 **Certificate Transparency** | `certificate`, `ct`, `domain`, `recon` | — |
| 13 | 🖼️ **Image / EXIF Recon** | `image`, `exif`, `metadata`, `osint` | — |
| 14 | ▶️ **YouTube Channel OSINT** | `youtube`, `social`, `osint`, `video` | — |
| 15 | 📋 **Website Contacts Scraper** | `contacts`, `email`, `scrape`, `recon` | — |
| 16 | 🔎 **Google Dorks Generator** | `dorks`, `google`, `osint`, `recon` | — |

## External Tools

| Tool | Description | Install | Requires Go |
|------|-------------|---------|-------------|
| **holehe** | Email → 120+ site registration check | `pip install holehe` | No |
| **maigret** | Username OSINT across 3000+ sites | `pip install maigret` | No |
| **theHarvester** | Emails, subdomains, IPs from public sources | `pip install git+https://github.com/laramies/theHarvester.git` | No |
| **subfinder** | Fast passive subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | Yes |
| **amass** | In-depth subdomain & attack surface mapping | `go install github.com/owasp-amass/amass/v4/...@master` | Yes |
| **trufflehog** | Find & verify leaked credentials in git repos | `pip install trufflehog` | No |
| **gitleaks** | Detect hardcoded secrets in git history | `go install github.com/gitleaks/gitleaks/v8@latest` | Yes |
| **instaloader** | Full Instagram profile & post OSINT | `pip install instaloader` | No |
