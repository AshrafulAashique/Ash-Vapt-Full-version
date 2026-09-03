# ══════════════════════════════════════════════════════════════════════
# Ash's VAPT & OSINT Intelligence Platform v3.0
# README.md — Full Project Description
# ══════════════════════════════════════════════════════════════════════

<div align="center">

<h1>🛡️ Ash's VAPT & OSINT Intelligence Platform</h1>
<p><strong>Advanced Vulnerability Assessment, Penetration Testing & OSINT Intelligence Dashboard</strong></p>

<p>
  <img src="https://img.shields.io/badge/version-3.0-blueviolet?style=for-the-badge" />
  <img src="https://img.shields.io/badge/python-3.9+-blue?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Flask-Backend-orange?style=for-the-badge&logo=flask" />
  <img src="https://img.shields.io/badge/WebGPU-AeroShards-A855F7?style=for-the-badge" />
</p>

<p>
  <a href="https://github.com/AshrafulAashique/Ash-s-VAPT-nd-OSINT-tool">
    <img src="https://img.shields.io/badge/🔗%20Repository-Ash's%20VAPT%20%26%20OSINT%20Tool-896ABD?style=for-the-badge&logo=github" />
  </a>
</p>

</div>

---

> **⚠️ Legal Notice:** Use only on systems you own or have **explicit written permission** to test.  
> Unauthorised scanning is **illegal** in most jurisdictions. The author assumes no liability.

---

## 📌 Overview

Ash's VAPT & OSINT Intelligence Platform is a comprehensive, professional-grade security assessment toolkit that combines **Vulnerability Assessment & Penetration Testing (VAPT)** with **Open Source Intelligence (OSINT)** gathering into a single unified dashboard.

The tool spins up a local **Flask-powered web dashboard** with a stunning glassmorphism UI, React WebGPU background effects, and real-time scanning feedback. All scan results are presented in the dashboard and can be exported.

**This is a local tool** — clone, install dependencies, and run it on your own machine. There is no hosted/cloud version.

---

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- Node.js 18+ (already bundled in the `dashboard/dist/` for the UI)

### 1. Clone the Repository
```bash
git clone https://github.com/AshrafulAashique/Ash-s-VAPT-nd-OSINT-tool.git
cd Ash-s-VAPT-nd-OSINT-tool
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch the Dashboard
```bash
python vapt_scanner.py
```

Or use the included launcher:
```bash
start.bat           # Windows
```

The browser opens automatically at **http://localhost:8765** — enter a target URL and click **Scan**.

---

## 🖥️ Dashboard Features

The dashboard is a modern, production-grade UI built with:

- **Glassmorphism cards** with `backdrop-filter` blur effects
- **Metallic matte typography** using multi-stop gradient text fills
- **React WebGPU AeroShards** background (touch/cursor interactive — repel mode)
- **Real-time progress** polling with animated status bar
- **Data masking** — sensitive fields (IPs, emails, ports) are partially obfuscated by default for privacy

---

## 🔍 What It Does — Module Breakdown

### 🌐 OSINT & Reconnaissance Modules

| Module | What It Collects |
|--------|-----------------|
| **DNS Enumeration** | A, AAAA, MX, NS, TXT, CNAME, SOA, CAA records + PTR (reverse DNS) |
| **IP Geolocation** | Country, ISP, ASN, city for all resolved IPs |
| **WHOIS / RDAP Lookup** | Registrar, creation/expiry dates, name servers, org, contact emails |
| **SSL/TLS Certificate Analysis** | Issuer, Subject, SANs, serial number, SHA-256 fingerprint, days-to-expiry, protocol version |
| **Subdomain Enumeration** | Brute-forces common subdomains, resolves live ones, maps IPs |
| **Port Scanning** | Scans top-risk ports (21, 22, 23, 25, 53, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017, etc.) |
| **Technology Fingerprinting** | CMS detection (WordPress, Joomla, Drupal), frameworks, CDN, JS libraries, analytics tools |
| **Email Harvesting** | Extracts emails from source code and linked pages |
| **Contact & Social Intel** | Phone numbers, social media handles, PII from visible page content |
| **HTML Comment Extraction** | Reveals developer comments, internal paths, TODOs, credentials left in source |
| **Linked Pages Mapping** | Crawls all internal/external links and JS resource paths |
| **Certificate Transparency Logs** | Queries crt.sh for historical certificate records and alternative domain names |
| **WAF Detection** | Identifies Web Application Firewall presence (Cloudflare, AWS WAF, Akamai, Sucuri, etc.) |
| **Sensitive File Discovery** | Probes for `.env`, `.git/config`, `wp-config.php`, `server-status`, backup files, DB dumps |

---

### 🛡️ Vulnerability Assessment Modules

| Module | What It Detects | Severity |
|--------|----------------|----------|
| **Security Headers** | Missing X-Frame-Options, HSTS, Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | Medium–High |
| **CORS Misconfiguration** | Wildcard `Access-Control-Allow-Origin: *`, credentialed CORS bypass | High–Critical |
| **CORS Preflight Bypass** | Dangerous methods exposed via OPTIONS requests | High |
| **Server Version Disclosure** | Leaking server name/version via `Server` or `X-Powered-By` headers | Medium |
| **SSL/TLS Issues** | Self-signed certs, expired certs, weak protocols (TLS 1.0/1.1), missing HTTPS redirect | Medium–Critical |
| **Clickjacking** | Missing `X-Frame-Options` + no `frame-ancestors` CSP directive | Medium |
| **Mixed Content** | HTTP resources loaded on HTTPS pages | Medium |
| **Insecure Cookies** | Missing `Secure`, `HttpOnly`, or `SameSite` cookie flags | Medium–High |
| **Cache Control Issues** | Sensitive pages served without `no-store` / `no-cache` | Low–Medium |
| **Directory Listing** | Open Apache/Nginx directory indexes exposing files | High |
| **Admin Panel Exposure** | Publicly accessible `/admin`, `/wp-admin`, `/phpmyadmin`, `/cpanel`, etc. | High–Critical |
| **Backup File Exposure** | `.bak`, `.old`, `.sql`, `.tar.gz`, `.zip` backup archives publicly accessible | High–Critical |
| **API Endpoint Exposure** | Unprotected REST API endpoints, GraphQL introspection, Swagger UIs | High |
| **HTTP Method Abuse** | TRACE, TRACK, PUT, DELETE enabled on web server | Medium–High |
| **robots.txt Analysis** | Sensitive path disclosure in `robots.txt` | Info–Low |
| **Outdated JS Libraries** | Detects vulnerable versions of jQuery, AngularJS, Bootstrap, React | Medium–High |
| **Subresource Integrity (SRI)** | External scripts/stylesheets lacking SRI hashes | Low–Medium |
| **Open Redirect** | Common redirect parameter injection vulnerabilities | Medium–High |
| **XSS Indicators** | Reflected input in form responses (reflected XSS indicator) | High–Critical |
| **Error Page Disclosure** | Stack traces, internal paths, DB connection strings in error pages | Medium |
| **JWT Weaknesses** | Weak signing secrets, `alg: none` bypass, token in URL | High–Critical |
| **WebSocket Detection** | Identifies exposed WebSocket endpoints and protocols | Info |
| **Path Traversal** | Directory traversal probes (`../`, `%2e%2e`) in URL parameters | High–Critical |
| **SSRF Indicators** | Server-Side Request Forgery candidate parameters detected | High–Critical |
| **Default Credentials** | Common admin/admin, root/root, etc. on login panels | Critical |
| **DNS Zone Transfer** | Attempts AXFR zone transfer leaking full DNS zone data | High–Critical |
| **DNS Email Security** | Missing/weak SPF, DMARC, and DNSSEC configuration | Low–Medium |

**Total: 14 OSINT Modules + 28 Vulnerability Checks = 42 automated security modules**

---

## 📊 Scoring & Grading

Results are automatically scored 0–100 with a security grade:

| Grade | Score | Meaning |
|-------|-------|---------|
| **A** | 85–100 | Strong security posture |
| **B** | 70–84  | Good, minor issues |
| **C** | 50–69  | Moderate risk, review needed |
| **D** | 25–49  | High risk, remediation urgent |
| **F** | 0–24   | Critical — immediate action required |

---

## 📦 Dashboard Panels

After a scan completes, the dashboard displays:

1. **Security Score & Grade** — Animated radial gauge (0-100)
2. **Severity Chart** — Visual breakdown of Critical / High / Medium / Low / Info findings
3. **IP Geolocation** — Country, ISP, ASN for all resolved IPs
4. **Registry Data (WHOIS)** — Domain registration info
5. **Cryptographic Cert** — Full SSL certificate details
6. **Exposed Services [Ports]** — Live port scan results
7. **Technology Signatures** — CMS, frameworks, analytics detected
8. **Perimeter Defense [WAF]** — WAF detection results
9. **Sensitive Artifacts** — Exposed backup/config files
10. **Intercepted Comms [Emails]** — Harvested email addresses
11. **Social Intel** — Contact info and social handles
12. **Source Code Leaks [Comments]** — Developer comments extracted
13. **Subdomain Enumeration** — Live subdomains found
14. **DNS Records** — Full DNS record listing
15. **Cert Transparency Logs** — crt.sh certificate history
16. **Vulnerability Report** — Full filterable findings table with OWASP mapping

---

## ⚙️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3 + Flask |
| Frontend | Vanilla HTML/JS + React |
| Background | WebGPU via `vgpu` + AeroShards (React Bits) |
| Build Tool | Vite + vite-plugin-singlefile |
| DNS | dnspython |
| HTTP | requests + BeautifulSoup |
| SSL | pyOpenSSL + cryptography |
| WHOIS | python-whois |

---

## 📁 Project Structure

```
Ash-s-VAPT-nd-OSINT-tool/
├── vapt_scanner.py          # Main scanner + Flask backend (1500 lines)
├── requirements.txt         # Python dependencies
├── start.bat               # Windows quick-launch script
├── dashboard/
│   ├── index.html          # Main dashboard UI (vanilla JS)
│   ├── main.jsx            # React AeroShards mount point
│   ├── AeroShards.jsx      # WebGPU background component
│   ├── AeroShards.css      # Component styles
│   ├── vite.config.js      # Vite build configuration
│   ├── package.json        # Node dependencies
│   └── dist/
│       └── index.html      # Built production bundle (served by Flask)
└── README.md
```

---

## 🔧 Rebuilding the Dashboard

If you modify `dashboard/index.html` or `main.jsx`, rebuild the bundle:

```bash
cd dashboard
npx vite build
```

The updated `dashboard/dist/index.html` will be automatically served next time you run the scanner.

---

## 📋 Dependencies

```
requests>=2.31.0
beautifulsoup4>=4.12.0
dnspython>=2.4.0
tqdm>=4.65.0
colorama>=0.4.6
pyOpenSSL>=23.0.0
cryptography>=41.0.0
python-whois>=0.8.0
flask>=3.0.0
```

---

## 🙏 Credits & Inspiration

Inspired by industry-leading security tools:
- [Vulners](https://vulners.com) — Vulnerability intelligence
- [Shodan](https://shodan.io) — Internet-facing device recon
- [SecurityHeaders.io](https://securityheaders.io) — Header analysis
- [crt.sh](https://crt.sh) — Certificate Transparency logs
- [React Bits](https://reactbits.dev) — AeroShards WebGPU background component

---

<div align="center">
  Made with ❤️ by <strong>AshrafulAashique</strong><br/>
  <a href="https://github.com/AshrafulAashique/Ash-s-VAPT-nd-OSINT-tool">⭐ Star this repo if it helped you!</a>
</div>
