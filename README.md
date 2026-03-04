# VAPT Analytical Platform

Automated Vulnerability Assessment & Penetration Testing tool.  
Scans a target website and generates a professional **DOCX report** with severity charts.

---

## Setup (one-time)

```bash
pip install requests beautifulsoup4 dnspython matplotlib python-docx Pillow tqdm colorama
```

Or install from the included file:
```bash
pip install -r requirements.txt
```

---

## Usage

```bash
python vapt_scanner.py <target_url>

# Examples:
python vapt_scanner.py https://example.com
python vapt_scanner.py http://testsite.local
```

---

## What it checks (15 automated modules)

| Module | Checks |
|--------|--------|
| Security Headers | X-Frame-Options, HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| CORS | Overly permissive `Access-Control-Allow-Origin: *` |
| Server Disclosure | Server version / X-Powered-By headers |
| SSL/TLS | Certificate validity, expiry, HTTP→HTTPS redirect |
| Cookies | Missing Secure / HttpOnly flags |
| Clickjacking | Missing X-Frame-Options + CSP frame-ancestors |
| Directory Listing | Common paths with open directory indexes |
| Sensitive Files | `.env`, `.git/config`, `wp-config.php`, `server-status` |
| HTTP Methods | TRACE / TRACK / PUT / DELETE enabled |
| robots.txt | Sensitive path disclosure |
| JS Libraries | Outdated/vulnerable jQuery, AngularJS, Bootstrap |
| Subresource Integrity | External scripts/styles missing SRI hashes |
| Open Redirect | Common redirect parameter injection |
| Input Validation | Reflected input in form responses (XSS indicator) |
| DNS / Email Security | SPF record, DMARC policy, DNSSEC |

---

## Output

A folder is created: `vapt_report_<domain>_<date>/`  
Inside:
- `VAPT_Report_<domain>.docx` — full professional report
- `bar_chart.png` — vulnerability count by severity
- `pie_chart.png` — severity distribution pie chart

### Report sections
1. **Cover page** — target, date, severity summary table
2. **Executive Summary** — plain-English overview
3. **Severity Distribution** — bar and pie charts embedded
4. **Summary Table** — all findings with ID, name, severity, OWASP mapping
5. **Detailed Findings** — per-vulnerability: description, evidence, OWASP, remediation, affected URLs
6. **Recommendations** — priority-ordered remediation actions

---

## Legal notice

> **Use only on systems you own or have explicit written permission to test.**  
> Unauthorised scanning is illegal in most jurisdictions.
