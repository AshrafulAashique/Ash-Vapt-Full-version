#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║         Ash's VAPT & OSINT Tool  —  Advanced Edition v3.0                   ║
║  Vulnerability Assessment + Penetration Testing + OSINT Intelligence        ║
║                                                                              ║
║  Inspired by: Vulners, Shodan-style recon, Spiderfoot, SpyFu, Censys,       ║
║               BuiltWith, SecurityHeaders.io, HaveIBeenPwned, DNSDumpster    ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    python vapt_scanner.py <target_url>
    python vapt_scanner.py https://example.com

Install dependencies:
    pip install requests beautifulsoup4 dnspython tqdm colorama pyOpenSSL cryptography python-whois flask
"""

import sys, os, re, ssl, json, socket, hashlib, datetime, urllib.parse
import ipaddress, time, threading, warnings, struct, base64, webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
warnings.filterwarnings("ignore")

# Force UTF-8 output on Windows to handle box-drawing / emoji characters
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# ── Third-party ───────────────────────────────────────────────────────────────
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    from bs4 import BeautifulSoup
    import dns.resolver, dns.reversename, dns.zone, dns.query
    from tqdm import tqdm
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    import OpenSSL.crypto as crypto
except ImportError as e:
    print(f"\n[!] Missing dependency: {e}")
    print("    pip install requests beautifulsoup4 dnspython tqdm colorama pyOpenSSL cryptography flask")
    sys.exit(1)

try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    from flask import Flask, jsonify, send_from_directory, request as flask_request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# ── Global scan state (shared between scanner thread & Flask) ─────────────────
SCAN_STATE = {
    "status":   "idle",      # idle | scanning | done | error
    "target":   "",
    "step":     "",
    "progress": 0,           # 0-100
    "total":    0,
    "current":  0,
    "results_path": None,
    "error":    "",
}

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS & MAPPINGS
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_ORDER  = ["Critical", "High", "Medium", "Low", "Info"]
SEVERITY_COLORS = {"Critical":"#C00000","High":"#FF4500","Medium":"#FFA500","Low":"#FFD700","Info":"#00BFFF"}

OWASP_MAP = {
    "Missing X-Frame-Options":           ("A05","Security Misconfiguration"),
    "Cross-Frame Scripting (XFS)":       ("A05","Security Misconfiguration"),
    "Missing HSTS Header":               ("A02","Cryptographic Failures"),
    "Missing Content-Security-Policy":   ("A05","Security Misconfiguration"),
    "Missing X-Content-Type-Options":    ("A05","Security Misconfiguration"),
    "Missing Referrer-Policy":           ("A05","Security Misconfiguration"),
    "Missing Permissions-Policy":        ("A05","Security Misconfiguration"),
    "Overly Permissive CORS":            ("A05","Security Misconfiguration"),
    "Server Version Disclosure":         ("A05","Security Misconfiguration"),
    "Open Redirect":                     ("A01","Broken Access Control"),
    "Clickjacking":                      ("A05","Security Misconfiguration"),
    "SSL/TLS Issues":                    ("A02","Cryptographic Failures"),
    "Insecure Cookies":                  ("A02","Cryptographic Failures"),
    "Missing HttpOnly Cookie Flag":      ("A07","Identification and Authentication Failures"),
    "Missing Secure Cookie Flag":        ("A02","Cryptographic Failures"),
    "Cookie Without SameSite":           ("A01","Broken Access Control"),
    "No Input Validation (Reflected)":   ("A03","Injection"),
    "SQL Injection Indicators":          ("A03","Injection"),
    "Directory Listing Enabled":         ("A05","Security Misconfiguration"),
    "DMARC Record Missing":              ("A05","Security Misconfiguration"),
    "DNSSEC Not Implemented":            ("A05","Security Misconfiguration"),
    "SPF Record Missing":                ("A05","Security Misconfiguration"),
    "Outdated Libraries Detected":       ("A06","Vulnerable and Outdated Components"),
    "HTTP Methods Enabled":              ("A05","Security Misconfiguration"),
    "robots.txt Sensitive Disclosure":   ("A01","Broken Access Control"),
    "Exposed Sensitive Files":           ("A05","Security Misconfiguration"),
    "Subresource Integrity Missing":     ("A08","Software and Data Integrity Failures"),
    "Error Message Information Leakage": ("A05","Security Misconfiguration"),
    "Admin Panel Exposed":               ("A01","Broken Access Control"),
    "Backup Files Accessible":           ("A05","Security Misconfiguration"),
    "API Endpoint Exposure":             ("A01","Broken Access Control"),
    "JWT Misconfiguration":              ("A02","Cryptographic Failures"),
    "Cache Control Issues":              ("A02","Cryptographic Failures"),
    "Mixed Content (HTTP in HTTPS)":     ("A02","Cryptographic Failures"),
    "Weak TLS Cipher Suite":             ("A02","Cryptographic Failures"),
    "Certificate Transparency Issues":   ("A02","Cryptographic Failures"),
    "DNS Zone Transfer Possible":        ("A05","Security Misconfiguration"),
    "Subdomain Takeover Risk":           ("A05","Security Misconfiguration"),
    "Open Ports Detected":               ("A05","Security Misconfiguration"),
    "Default Credentials Hint":          ("A07","Identification and Authentication Failures"),
    "Email Addresses Harvested":         ("A01","Broken Access Control"),
    "Sensitive Comments in Source":      ("A05","Security Misconfiguration"),
    "WebSocket Without TLS":             ("A02","Cryptographic Failures"),
    "Path Traversal Indicators":         ("A01","Broken Access Control"),
    "SSRF Surface Detected":             ("A10","Server-Side Request Forgery"),
    "Weak Password Policy Page":         ("A07","Identification and Authentication Failures"),
    "Insecure Deserialization Hints":    ("A08","Software and Data Integrity Failures"),
}

REMEDIATION = {
    "Missing X-Frame-Options":("Add `X-Frame-Options: DENY` or `SAMEORIGIN` to all responses.","Medium"),
    "Missing HSTS Header":("Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.","Medium"),
    "Missing Content-Security-Policy":("Define a strict CSP header to mitigate XSS.","Medium"),
    "Missing X-Content-Type-Options":("Add `X-Content-Type-Options: nosniff` header.","Low"),
    "Missing Referrer-Policy":("Set `Referrer-Policy: strict-origin-when-cross-origin`.","Low"),
    "Missing Permissions-Policy":("Add `Permissions-Policy` to restrict browser feature access.","Low"),
    "Overly Permissive CORS":("Replace wildcard CORS with a strict trusted-origin allowlist.","Medium"),
    "Server Version Disclosure":("Suppress version info from Server and X-Powered-By headers.","Low"),
    "SSL/TLS Issues":("Use TLS 1.2+ only; renew certificates; enforce HTTPS redirect.","High"),
    "Insecure Cookies":("Set Secure, HttpOnly, and SameSite=Strict on all session cookies.","Medium"),
    "Missing HttpOnly Cookie Flag":("Add HttpOnly flag to all cookies not requiring JS access.","Medium"),
    "Missing Secure Cookie Flag":("Add Secure flag so cookies are only transmitted over HTTPS.","Medium"),
    "Cookie Without SameSite":("Add SameSite=Strict or Lax to all cookies to prevent CSRF.","Medium"),
    "No Input Validation (Reflected)":("Apply server-side input validation and HTML-encode all output.","High"),
    "SQL Injection Indicators":("Use parameterised queries / prepared statements exclusively.","Critical"),
    "Directory Listing Enabled":("Disable directory listing in server config.","Medium"),
    "DMARC Record Missing":("Publish a DMARC record to protect against email spoofing.","Low"),
    "DNSSEC Not Implemented":("Enable DNSSEC at your DNS registrar.","Low"),
    "SPF Record Missing":("Publish an SPF TXT record authorising your mail senders.","Low"),
    "Outdated Libraries Detected":("Update all third-party JS libraries to latest stable versions.","Medium"),
    "HTTP Methods Enabled":("Disable TRACE, TRACK, PUT, DELETE unless explicitly required.","Medium"),
    "robots.txt Sensitive Disclosure":("Remove sensitive paths from robots.txt; use real access controls.","Low"),
    "Exposed Sensitive Files":("Block access to .env, .git, config files via web server deny rules.","High"),
    "Subresource Integrity Missing":("Add integrity and crossorigin attributes to all external resources.","Low"),
    "Error Message Information Leakage":("Return generic error messages; log details server-side only.","Medium"),
    "Admin Panel Exposed":("Move admin interfaces behind VPN or IP whitelist; enforce MFA.","High"),
    "Backup Files Accessible":("Remove all backup files from web root; deny .bak/.sql in server config.","High"),
    "API Endpoint Exposure":("Require authentication on all API endpoints; apply rate limiting.","High"),
    "JWT Misconfiguration":("Validate JWT algorithm, expiry, and signature; reject 'none' algorithm.","High"),
    "Cache Control Issues":("Add `Cache-Control: no-store` on sensitive pages.","Medium"),
    "Mixed Content (HTTP in HTTPS)":("Load all resources over HTTPS; update all hardcoded HTTP URLs.","Medium"),
    "Weak TLS Cipher Suite":("Disable weak ciphers (RC4, DES, 3DES); use ECDHE+AES256.","High"),
    "Certificate Transparency Issues":("Monitor CT logs for unauthorised certificate issuance.","Medium"),
    "DNS Zone Transfer Possible":("Restrict AXFR transfers to authorised secondary DNS IPs only.","High"),
    "Subdomain Takeover Risk":("Remove or re-point dangling DNS records to active services.","High"),
    "Open Ports Detected":("Close or firewall unnecessary open ports; document all services.","Medium"),
    "Default Credentials Hint":("Change default credentials immediately; enforce strong password policy.","Critical"),
    "Email Addresses Harvested":("Obfuscate email addresses on public pages to prevent harvesting.","Low"),
    "Sensitive Comments in Source":("Remove developer comments with paths, credentials, or logic from production.","Low"),
    "WebSocket Without TLS":("Use wss:// (WebSocket Secure) instead of ws://.","Medium"),
    "Path Traversal Indicators":("Validate and sanitise all file path inputs; use allowlists.","High"),
    "SSRF Surface Detected":("Validate and whitelist all server-side URL fetch targets; block internal IPs.","High"),
    "Open Redirect":("Validate redirect URLs against a strict whitelist server-side.","Medium"),
    "Clickjacking":("Set X-Frame-Options: DENY and CSP frame-ancestors 'none'.","Medium"),
    "Weak Password Policy Page":("Enforce 12+ char passwords, rate limiting, and MFA.","High"),
    "Insecure Deserialization Hints":("Avoid deserialising untrusted data; use safe serialisation formats.","High"),
    "Cross-Frame Scripting (XFS)":("Implement X-Frame-Options: SAMEORIGIN and CSP frame-ancestors 'self'.","Medium"),
}


SESSION = requests.Session()
SESSION.headers.update({"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"})
SESSION.verify = False


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def banner():
    try:
        print(Fore.RED + """
  ___   ___ _  _ ___   __   __   _   ___ _____   ___  ___ ___ _  _ _____
 / _ \\ / __| || |_ _| \\ \\ / /  /_\\ |_ _|_   _| / _ \\/ __|_ _| \\| |_   _|
| (_) | (__| __ || |   \\ V /  / _ \\ | |  | |  | (_) \\__ \\| || .` | | |
 \\___/ \\___|_||_|___|   \\_/  /_/ \\_\\___| |_|   \\___/|___/___|_|\\_| |_|

  Ash's VAPT & OSINT Tool v3.0  --  Dashboard Edition
  ====================================================
""" + Style.RESET_ALL)
    except Exception:
        print("[*] Ash's VAPT & OSINT Tool v3.0")

def normalise_url(url):
    if not url.startswith(("http://","https://")):
        url = "https://" + url
    return url.rstrip("/")

def get_domain(url):
    return urllib.parse.urlparse(url).netloc.split(":")[0]

def safe_get(url, timeout=10, allow_redirects=True, headers=None):
    try:
        h = dict(SESSION.headers)
        if headers:
            h.update(headers)
        return SESSION.get(url, timeout=timeout, allow_redirects=allow_redirects, headers=h, verify=False)
    except Exception:
        return None

def ip_to_geo(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,org,as,query",
                         timeout=6)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}

def calculate_security_score(findings):
    score = 100
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] += 1

    score -= min(counts["Critical"] * 20, 60)
    score -= min(counts["High"]     * 10, 40)
    score -= min(counts["Medium"]   *  5, 20)
    score -= min(counts["Low"]      *  2, 10)
    score = max(0, score)

    if score >= 85:
        grade, color = "A", "#00C853"
    elif score >= 70:
        grade, color = "B", "#00BCD4"
    elif score >= 50:
        grade, color = "C", "#FF9800"
    elif score >= 25:
        grade, color = "D", "#F44336"
    else:
        grade, color = "F", "#B71C1C"

    return {"score": score, "grade": grade, "color": color}


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN SCANNER CLASS
# ─────────────────────────────────────────────────────────────────────────────

class VAPTScanner:
    def __init__(self, target):
        self.target   = normalise_url(target)
        self.domain   = get_domain(self.target)
        self.findings = []
        self.intel    = {}
        self._resp    = None

    def _add(self, name, evidence, detail, urls=None, severity=None):
        if name not in OWASP_MAP or name not in REMEDIATION:
            return
        owasp_id, owasp_name = OWASP_MAP.get(name,("A05","Security Misconfiguration"))
        remedy, sev = REMEDIATION.get(name,("Review and remediate.","Info"))
        if severity:
            sev = severity
        self.findings.append({
            "id":        f"V-{len(self.findings)+1:02d}",
            "name":      name,
            "severity":  sev,
            "owasp_id":  owasp_id,
            "owasp_name":owasp_name,
            "evidence":  evidence,
            "detail":    detail,
            "remedy":    remedy,
            "urls":      urls or [self.target],
        })

    def _main(self):
        if self._resp is None:
            self._resp = safe_get(self.target)
        return self._resp

    # ══════════════════════════════════════════════════════════════════════
    #   OSINT & RECON MODULES
    # ══════════════════════════════════════════════════════════════════════

    def recon_dns(self):
        info = {}
        for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA"]:
            try:
                answers = dns.resolver.resolve(self.domain, rtype, lifetime=5)
                info[rtype] = [str(r) for r in answers]
            except Exception:
                info[rtype] = []
        ptr_map = {}
        for ip in info.get("A",[])[:3]:
            try:
                rev = dns.reversename.from_address(ip)
                ptr_answers = dns.resolver.resolve(rev,"PTR",lifetime=4)
                ptr_map[ip] = str(ptr_answers[0])
            except Exception:
                ptr_map[ip] = "No PTR record"
        info["PTR_MAP"] = ptr_map
        self.intel["dns"] = info

    def recon_ip_info(self):
        ips = []
        try:
            ips = [str(r) for r in dns.resolver.resolve(self.domain,"A",lifetime=5)]
        except Exception:
            try:
                ips = [socket.gethostbyname(self.domain)]
            except Exception:
                pass
        geo_results = []
        for ip in ips[:3]:
            geo = ip_to_geo(ip)
            geo_results.append({"ip":ip, **geo})
        self.intel["ip_info"] = geo_results

    def recon_whois(self):
        data = {}
        if WHOIS_AVAILABLE:
            try:
                w = whois_lib.whois(self.domain)
                def first(v):
                    return str(v[0] if isinstance(v,list) else v or "N/A")
                data = {
                    "registrar":    first(w.registrar),
                    "creation_date":first(w.creation_date),
                    "expiry_date":  first(w.expiration_date),
                    "updated_date": first(w.updated_date),
                    "name_servers": list(set([str(n).lower() for n in (w.name_servers or [])])),
                    "status":       first(w.status),
                    "org":          str(w.org or w.registrant_name or "N/A"),
                    "country":      str(w.country or "N/A"),
                    "emails":       list(set(w.emails)) if isinstance(w.emails,list) else ([w.emails] if w.emails else []),
                }
                exp = w.expiration_date
                if isinstance(exp,list): exp = exp[0]
                if exp and isinstance(exp,datetime.datetime):
                    days = (exp - datetime.datetime.utcnow()).days
                    if days < 30:
                        self._add("SSL/TLS Issues",
                            f"Domain expires in {days} days ({exp.date()})",
                            "Domain registration nearing expiry — risk of accidental lapse.",
                            severity="High")
            except Exception as e:
                data = {"error": str(e)}
        else:
            try:
                r = requests.get(f"https://rdap.verisign.com/com/v1/domain/{self.domain}",timeout=8)
                if r.status_code == 200:
                    j = r.json()
                    for event in j.get("events",[]):
                        if event.get("eventAction") == "registration":
                            data["creation_date"] = event.get("eventDate","N/A")
                        if event.get("eventAction") == "expiration":
                            data["expiry_date"] = event.get("eventDate","N/A")
            except Exception:
                data["note"] = "Install python-whois for full WHOIS data: pip install python-whois"
        self.intel["whois"] = data

    def recon_ssl_certificate(self):
        cert_info = {}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.domain,443),timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    raw = ssock.getpeercert(binary_form=True)
                    pem = ssl.DER_cert_to_PEM_cert(raw)
                    cert_info["protocol"] = ssock.version()
                    cert_info["cipher"]   = ssock.cipher()
                    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
                    subj = x509.get_subject()
                    cert_info["subject"]  = {"CN":subj.CN,"O":subj.O,"C":subj.C}
                    issuer = x509.get_issuer()
                    cert_info["issuer"]   = {"CN":issuer.CN,"O":issuer.O}
                    cert_info["serial"]   = str(x509.get_serial_number())
                    cert_info["not_after"]= x509.get_notAfter().decode()
                    cert_info["sha256_fp"]= x509.digest("sha256").decode()
                    sans = []
                    for i in range(x509.get_extension_count()):
                        ext = x509.get_extension(i)
                        if ext.get_short_name() == b"subjectAltName":
                            sans = [s.strip() for s in str(ext).split(",")]
                    cert_info["san"] = sans
                    exp_str = x509.get_notAfter().decode()
                    exp_dt = datetime.datetime.strptime(exp_str,"%Y%m%d%H%M%SZ")
                    days = (exp_dt - datetime.datetime.utcnow()).days
                    cert_info["days_until_expiry"] = days
                    if days < 0:
                        self._add("SSL/TLS Issues",f"Certificate EXPIRED {abs(days)} days ago",
                            "SSL certificate has expired — all HTTPS connections show a security warning.",severity="Critical")
                    elif days < 30:
                        self._add("SSL/TLS Issues",f"Certificate expires in {days} days",
                            "Certificate near expiry — renew immediately.",severity="High")
                    proto = ssock.version()
                    if proto in ("SSLv2","SSLv3","TLSv1","TLSv1.1"):
                        self._add("Weak TLS Cipher Suite",f"Protocol: {proto}",
                            f"{proto} is deprecated and vulnerable to known attacks (BEAST, POODLE).",severity="High")
                    cipher_name = ssock.cipher()[0] if ssock.cipher() else ""
                    for wc in ["RC4","DES","3DES","EXPORT","NULL","anon"]:
                        if wc.lower() in cipher_name.lower():
                            self._add("Weak TLS Cipher Suite",f"Weak cipher: {cipher_name}",
                                f"Cipher {cipher_name} is cryptographically weak.",severity="High")
                            break
        except ssl.SSLError as e:
            cert_info["error"] = str(e)
            self._add("SSL/TLS Issues",f"SSL error: {e}","SSL/TLS configuration error.",severity="High")
        except Exception as e:
            cert_info["error"] = str(e)
        self.intel["ssl"] = cert_info

    def recon_subdomains(self):
        wordlist = [
            "www","mail","remote","blog","webmail","server","ns1","ns2","smtp","secure",
            "vpn","m","shop","ftp","mail2","test","portal","ns","ww1","host","support",
            "dev","web","bbs","ww42","mx","email","1","mail1","2","forum","owa","www2",
            "gw","admin","store","mx1","cdn","api","exchange","app","archive","beta",
            "cpanel","whm","autodiscover","autoconfig","irc","news","media","crm",
            "staging","office","chat","direct","dashboard","login","auth","status",
            "monitor","db","mysql","oracle","sql","demo","git","svn","jira","confluence",
            "jenkins","grafana","kibana","docs","help","wiki","intranet","internal",
            "vpn2","remote2","extranet","partner","customer","portal2","new","old",
        ]
        found = []
        takeover_services = ["s3.amazonaws.com","github.io","heroku.com","azurewebsites.net",
                             "cloudfront.net","wordpress.com","shopify.com","fastly.net"]

        def check_sub(sub):
            fqdn = f"{sub}.{self.domain}"
            try:
                answers = dns.resolver.resolve(fqdn,"A",lifetime=2)
                ips = [str(r) for r in answers]
                return {"subdomain":fqdn,"ips":ips}
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=40) as exe:
            for result in exe.map(check_sub, wordlist):
                if result:
                    found.append(result)

        for sub in found:
            fqdn = sub["subdomain"]
            try:
                cnames = dns.resolver.resolve(fqdn,"CNAME",lifetime=3)
                for cn in cnames:
                    cval = str(cn.target).lower()
                    for svc in takeover_services:
                        if svc in cval:
                            r = safe_get(f"https://{fqdn}",timeout=4)
                            if not r or r.status_code in (404,503):
                                self._add("Subdomain Takeover Risk",
                                    f"{fqdn} CNAME → {cval} (service may be unclaimed)",
                                    "CNAME points to an unclaimed cloud service — attacker can claim it.",
                                    [f"https://{fqdn}"],severity="High")
            except Exception:
                pass

        self.intel["subdomains"] = sorted(found, key=lambda x:x["subdomain"])

    def recon_port_scan(self):
        PORTS = {
            21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
            80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",
            3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5900:"VNC",
            6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"HTTP-Dev",
            9200:"Elasticsearch",27017:"MongoDB",11211:"Memcached",
            2375:"Docker API",4848:"GlassFish",7001:"WebLogic",
            8161:"ActiveMQ",9090:"Cockpit",6443:"Kubernetes API",
        }
        try:
            ip = socket.gethostbyname(self.domain)
        except Exception:
            self.intel["ports"] = []
            return

        open_ports = []
        def check_port(port):
            try:
                with socket.create_connection((ip,port),timeout=1.2):
                    return port
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=60) as exe:
            results = list(exe.map(check_port, PORTS.keys()))

        for port in results:
            if port:
                service = PORTS.get(port,"Unknown")
                risk = "critical" if port in (23,445,2375,4848,7001,5900) else \
                       "high" if port in (3389,6379,9200,27017,11211) else \
                       "medium" if port in (21,3306,5432,8888) else "low"
                open_ports.append({"port":port,"service":service,"risk":risk})
                if port in (23,445,3389,5900,6379,9200,27017,11211,2375,4848,7001):
                    self._add("Open Ports Detected",f"Port {port} ({service}) open on {ip}",
                        f"{service} on port {port} should not be publicly accessible.",severity="High")
                elif port in (21,3306,5432,8888):
                    self._add("Open Ports Detected",f"Port {port} ({service}) open",
                        f"{service} port publicly accessible — restrict to internal network.",severity="Medium")

        self.intel["ports"] = open_ports

    def recon_technologies(self):
        r = self._main()
        if not r:
            self.intel["technologies"] = {}
            return
        body    = r.text.lower()
        headers = {k.lower():v for k,v in r.headers.items()}
        soup    = BeautifulSoup(r.text,"html.parser")
        tech    = {}

        cms_sigs = {
            "WordPress":   ["wp-content","wp-includes","wp-json"],
            "Drupal":      ["drupal.js","drupal.min.js","/sites/default/"],
            "Joomla":      ["/components/com_","joomla"],
            "Magento":     ["mage/","magento","varien"],
            "Shopify":     ["cdn.shopify.com","shopify.com/s/"],
            "Wix":         ["wixsite.com","wix.com/"],
            "Squarespace": ["squarespace.com","static1.squarespace"],
            "Ghost":       ["ghost.io","content/images/"],
            "PrestaShop":  ["prestashop","presta_shop"],
            "OpenCart":    ["opencart","route=common"],
        }
        for name, sigs in cms_sigs.items():
            if any(s in body for s in sigs):
                tech["CMS"] = name
                break

        server = headers.get("server","")
        if server: tech["Server"] = server
        powered = headers.get("x-powered-by","")
        if powered: tech["Framework"] = powered

        cdn_sigs = {
            "Cloudflare":        ["cf-ray","cf-cache-status"],
            "Fastly":            ["x-served-by","x-cache"],
            "Akamai":            ["x-check-cacheable","x-akamai"],
            "Amazon CloudFront": ["x-amz-cf-id","cloudfront"],
            "Azure CDN":         ["x-azure-ref"],
            "BunnyCDN":          ["bunnycdn","bunny.net"],
        }
        for cdn, hdrs in cdn_sigs.items():
            if any(h in headers or h in body for h in hdrs):
                tech["CDN"] = cdn
                break

        waf_sigs = {
            "Cloudflare WAF": ["cf-ray"],
            "AWS WAF":        ["x-amzn-requestid","awselb"],
            "Sucuri":         ["x-sucuri-id"],
            "Incapsula":      ["x-iinfo","incap_ses"],
            "F5 BIG-IP":      ["bigipserver"],
            "Barracuda":      ["barra_counter_session"],
            "ModSecurity":    ["mod_security","modsec"],
            "Imperva":        ["x-iinfo"],
        }
        detected_waf = "None detected"
        for waf, sigs in waf_sigs.items():
            if any(s in headers or s in body for s in sigs):
                detected_waf = waf
                break
        tech["WAF"] = detected_waf

        js_sigs = {
            "React":     ["react.js","react.min.js","react-dom","__reactfiber"],
            "Vue.js":    ["vue.js","vue.min.js","__vue__"],
            "Angular":   ["angular.js","ng-version","angular.min"],
            "jQuery":    ["jquery.js","jquery.min.js","jquery-"],
            "Bootstrap": ["bootstrap.js","bootstrap.min","bootstrap.css"],
            "Next.js":   ["_next/","__next"],
            "Nuxt.js":   ["_nuxt/","nuxtjs"],
            "Ember.js":  ["ember.js","ember.min"],
            "Svelte":    ["svelte","__svelte"],
            "Alpine.js": ["alpine.js","x-data="],
        }
        frameworks = [name for name,sigs in js_sigs.items() if any(s in body for s in sigs)]
        if frameworks: tech["JS Frameworks"] = ", ".join(frameworks)

        analytics_sigs = {
            "Google Analytics":   ["google-analytics.com","gtag/js","UA-","G-"],
            "Google Tag Manager": ["googletagmanager.com"],
            "Facebook Pixel":     ["connect.facebook.net","fbq("],
            "HotJar":             ["hotjar.com","hjSetting"],
            "Mixpanel":           ["mixpanel.com"],
            "Segment.io":         ["segment.com","analytics.js"],
            "Intercom":           ["intercom.io"],
            "Crisp":              ["crisp.chat"],
            "Zendesk":            ["zendesk.com","zopim"],
        }
        analytics = [name for name,sigs in analytics_sigs.items() if any(s in body for s in sigs)]
        tech["Analytics/Tracking"] = analytics or ["None detected"]

        mx_records = self.intel.get("dns",{}).get("MX",[])
        if mx_records:
            mx_str = " ".join(mx_records).lower()
            if "google" in mx_str or "gmail" in mx_str:
                tech["Email Provider"] = "Google Workspace"
            elif "outlook" in mx_str or "microsoft" in mx_str:
                tech["Email Provider"] = "Microsoft 365"
            elif "amazonses" in mx_str:
                tech["Email Provider"] = "Amazon SES"
            else:
                tech["Email Provider"] = mx_records[0] if mx_records else "Unknown"

        payment_sigs = {"Stripe":["stripe.com","stripe.js"],"PayPal":["paypal.com","paypaljs"],
                        "Braintree":["braintree","braintreepayments"],"Square":["squareup.com"]}
        payments = [n for n,s in payment_sigs.items() if any(x in body for x in s)]
        if payments: tech["Payment Processors"] = ", ".join(payments)

        self.intel["technologies"] = tech

    def recon_email_harvest(self):
        r = self._main()
        if not r: return
        emails = list(set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", r.text)))
        emails = [e for e in emails if not any(x in e.lower() for x in
                  ["example.com","w3.org","schema.org","sentry.io","jquery.com"])]
        if emails:
            self._add("Email Addresses Harvested",
                f"{len(emails)} email(s): {', '.join(emails[:5])}",
                "Email addresses in page source can be harvested for phishing and spam.")
        self.intel["emails"] = emails

    def recon_contacts(self):
        """Harvest phone numbers, social media links, and contact info from the main page."""
        r = self._main()
        if not r:
            self.intel["contacts"] = {}
            return
        text = r.text
        # Phone numbers (international + local patterns)
        phones = list(set(re.findall(r'(?:\+?\d[\d\s\-\(\)]{7,}\d)', text)))
        phones = [p.strip() for p in phones if len(re.sub(r'\D','',p)) >= 7][:20]

        # Social media
        social_patterns = {
            "Twitter/X":   r'(?:twitter\.com|x\.com)/([A-Za-z0-9_]{1,50})',
            "LinkedIn":    r'linkedin\.com/(?:in|company)/([A-Za-z0-9\-]{1,80})',
            "Facebook":    r'facebook\.com/([A-Za-z0-9.\-]{1,80})',
            "Instagram":   r'instagram\.com/([A-Za-z0-9._]{1,50})',
            "GitHub":      r'github\.com/([A-Za-z0-9\-]{1,80})',
            "YouTube":     r'youtube\.com/(?:c/|channel/|user/)?([A-Za-z0-9\-_]{1,80})',
        }
        social = {}
        for platform, pattern in social_patterns.items():
            matches = list(set(re.findall(pattern, text, re.I)))
            if matches:
                social[platform] = matches[:3]

        # POC / contact form URLs
        soup = BeautifulSoup(text, "html.parser")
        contact_links = []
        for a in soup.find_all("a", href=True):
            href = a.get("href","").lower()
            label = a.get_text(strip=True).lower()
            if any(k in href or k in label for k in ["contact","support","team","about","poc","reach"]):
                full = a["href"] if a["href"].startswith("http") else f"https://{self.domain}{a['href']}"
                contact_links.append({"label": a.get_text(strip=True)[:60], "url": full})

        self.intel["contacts"] = {
            "phones": phones,
            "social": social,
            "contact_pages": contact_links[:10],
        }

    def recon_source_comments(self):
        r = self._main()
        if not r: return
        comments = re.findall(r"<!--(.*?)-->", r.text, re.DOTALL)
        keywords = ["todo","fixme","hack","bug","password","secret","key","token",
                    "admin","credential","database","api","remove","temp","debug","localhost"]
        interesting = []
        for c in comments:
            c_clean = c.strip()
            if any(k in c_clean.lower() for k in keywords) and len(c_clean) > 5:
                interesting.append(c_clean[:200])
        if interesting:
            self._add("Sensitive Comments in Source",
                f"{len(interesting)} sensitive comment(s) found.",
                "HTML comments contain sensitive keywords (passwords, API keys, TODOs).")
        self.intel["source_comments"] = interesting

    def recon_linked_pages(self):
        r = self._main()
        if not r: return
        soup = BeautifulSoup(r.text,"html.parser")
        links = set()
        base = f"https://{self.domain}"
        for a in soup.find_all("a",href=True):
            href = a["href"]
            if href.startswith("/"):
                links.add(base + href)
            elif self.domain in href:
                links.add(href)
        self.intel["internal_links"] = list(links)[:50]

    def recon_ct_logs(self):
        certs = []
        try:
            r = requests.get(f"https://crt.sh/?q=%.{self.domain}&output=json",
                             timeout=10, headers={"User-Agent":"VAPT-Scanner/3.0"})
            if r.status_code == 200:
                data = r.json()
                seen = set()
                for entry in data[:100]:
                    name = entry.get("name_value","").strip()
                    logged = entry.get("entry_timestamp","")
                    for n in name.split("\n"):
                        n = n.strip().lower()
                        if n and n not in seen:
                            seen.add(n)
                            certs.append({"domain":n,"logged":logged[:10] if logged else "unknown"})
        except Exception:
            pass
        self.intel["ct_logs"] = certs[:50]
        wild = [c for c in certs if c["domain"].startswith("*")]
        if wild:
            self._add("Certificate Transparency Issues",
                f"{len(wild)} wildcard certificate(s) in CT logs.",
                "Wildcard certificates in public CT logs — monitor for unexpected issuance.")

    def recon_waf_detection(self):
        waf_info = {"detected":False,"product":"None"}
        payloads = ["?q=<script>alert(1)</script>","?id=1' OR '1'='1","?file=../../../../etc/passwd"]
        for p in payloads:
            r = safe_get(self.target + p, timeout=6, allow_redirects=False)
            if r:
                hdrs = {k.lower():v for k,v in r.headers.items()}
                if r.status_code in (403,406,429,503):
                    waf_info["detected"] = True
                    if "cf-ray" in hdrs:
                        waf_info["product"] = "Cloudflare"
                    elif "x-sucuri-id" in hdrs:
                        waf_info["product"] = "Sucuri"
                    elif "x-iinfo" in hdrs:
                        waf_info["product"] = "Incapsula/Imperva"
                    else:
                        waf_info["product"] = "Unknown WAF"
                    break
        self.intel["waf"] = waf_info

    def recon_extractable_files(self):
        """Check for files that may be downloaded/extracted — sensitive docs, data files, configs."""
        targets = [
            ("/.env","Environment file","Critical"),
            ("/.env.local","Local env","Critical"),
            ("/.env.production","Prod env","Critical"),
            ("/.git/config","Git config","High"),
            ("/.git/HEAD","Git HEAD","High"),
            ("/config.php","PHP config","High"),
            ("/wp-config.php","WP config","High"),
            ("/wp-config.php.bak","WP config backup","High"),
            ("/.htaccess","Apache config","Medium"),
            ("/server-status","Apache status","Medium"),
            ("/phpinfo.php","PHP info","Medium"),
            ("/info.php","PHP info","Medium"),
            ("/adminer.php","Adminer","High"),
            ("/phpmyadmin/","phpMyAdmin","High"),
            ("/database.sql","SQL dump","Critical"),
            ("/backup.sql","SQL backup","Critical"),
            ("/web.config","IIS config","High"),
            ("/crossdomain.xml","Flash crossdomain","Low"),
            ("/.DS_Store","macOS DS_Store","Low"),
            ("/npm-debug.log","npm log","Low"),
            ("/yarn-error.log","Yarn log","Low"),
            ("/composer.json","Composer manifest","Low"),
            ("/package.json","NPM manifest","Low"),
            ("/.travis.yml","CI config","Medium"),
            ("/Dockerfile","Dockerfile","Medium"),
            ("/docker-compose.yml","Docker Compose","Medium"),
            ("/sitemap.xml","Sitemap","Info"),
            ("/robots.txt","Robots.txt","Info"),
            ("/security.txt","Security.txt","Info"),
            ("/.well-known/security.txt","Security.txt","Info"),
        ]
        found_files = []
        for path, label, risk in targets:
            url = self.target + path
            r = safe_get(url, timeout=5)
            if r and r.status_code == 200 and len(r.text.strip()) > 5:
                extractable = True
                if risk in ("Critical","High"):
                    if any(kw in r.text.lower() for kw in ["db_","database","password","secret","api_key","php","[core]","ref:","from","env","port"]):
                        self._add("Exposed Sensitive Files", f"{label} at {url}",
                            f"'{path}' publicly accessible — may expose credentials or configuration.",
                            [url], severity=risk)
                found_files.append({
                    "path": path,
                    "label": label,
                    "url": url,
                    "risk": risk,
                    "size": len(r.content),
                    "content_type": r.headers.get("Content-Type",""),
                })
        self.intel["extractable_files"] = found_files

    # ══════════════════════════════════════════════════════════════════════
    #   VULNERABILITY CHECKS (40+)
    # ══════════════════════════════════════════════════════════════════════

    def check_security_headers(self):
        r = self._main()
        if not r: return
        headers = {k.lower():v for k,v in r.headers.items()}
        checks = [
            ("x-frame-options","Missing X-Frame-Options","X-Frame-Options absent — pages embeddable in iframes, enabling clickjacking."),
            ("strict-transport-security","Missing HSTS Header","HSTS absent — browsers may connect over plain HTTP, enabling SSL-stripping."),
            ("content-security-policy","Missing Content-Security-Policy","No CSP — XSS and data-injection risk significantly elevated."),
            ("x-content-type-options","Missing X-Content-Type-Options","X-Content-Type-Options absent — MIME-type sniffing possible."),
            ("referrer-policy","Missing Referrer-Policy","Referrer-Policy absent — URL parameters may leak to third-party sites."),
            ("permissions-policy","Missing Permissions-Policy","Permissions-Policy absent — browser features unrestricted for embedded content."),
        ]
        for hdr, vuln, detail in checks:
            if hdr not in headers:
                self._add(vuln, f"Header '{hdr}' not present.", detail)

    def check_cors(self):
        r = self._main()
        if not r: return
        acao = r.headers.get("Access-Control-Allow-Origin","")
        acac = r.headers.get("Access-Control-Allow-Credentials","")
        if acao.strip() == "*":
            detail = "Wildcard CORS — any origin can make cross-origin requests."
            sev = "Critical" if acac.lower() == "true" else "Medium"
            self._add("Overly Permissive CORS",f"ACAO: {acao} ACAC: {acac}",detail,severity=sev)

    def check_cors_preflight(self):
        try:
            r = SESSION.options(self.target,timeout=7,verify=False,headers={
                "Origin":"https://evil-attacker.com",
                "Access-Control-Request-Method":"GET",
            })
            acao = r.headers.get("Access-Control-Allow-Origin","")
            if "evil-attacker.com" in acao:
                self._add("Overly Permissive CORS",
                    f"Server reflects arbitrary Origin: {acao}",
                    "Origin header reflected without validation — full CORS bypass possible.",severity="High")
        except Exception:
            pass

    def check_server_disclosure(self):
        r = self._main()
        if not r: return
        tokens = []
        for h in ["Server","X-Powered-By","X-AspNet-Version","X-AspNetMvc-Version","X-Generator"]:
            v = r.headers.get(h,"")
            if v: tokens.append(f"{h}: {v}")
        if tokens:
            self._add("Server Version Disclosure","; ".join(tokens),
                "Server advertising software/version — aids attacker CVE research.")

    def check_ssl(self):
        http_url = self.target.replace("https://","http://",1)
        r = safe_get(http_url,allow_redirects=False,timeout=6)
        if r and r.status_code not in (301,302,307,308):
            self._add("SSL/TLS Issues",f"HTTP {http_url} returned {r.status_code} (no HTTPS redirect)",
                "Plain HTTP not redirected to HTTPS — data transmitted in cleartext.",severity="High")

    def check_clickjacking(self):
        r = self._main()
        if not r: return
        xfo = r.headers.get("X-Frame-Options","").upper()
        csp = r.headers.get("Content-Security-Policy","")
        if not xfo and "frame-ancestors" not in csp.lower():
            self._add("Clickjacking","Neither X-Frame-Options nor CSP frame-ancestors found.",
                "Page embeddable in any iframe — trivially clickjackable.")

    def check_mixed_content(self):
        r = self._main()
        if not r or not self.target.startswith("https://"): return
        http_links = re.findall(r'(?:src|href)=["\']http://[^"\']+["\']',r.text,re.I)
        if http_links:
            self._add("Mixed Content (HTTP in HTTPS)",
                f"{len(http_links)} HTTP resource(s) in HTTPS page: {http_links[0][:80]}",
                "HTTP resources in HTTPS page — assets exposed to MITM interception.")

    def check_cookies(self):
        r = self._main()
        if not r: return
        reported = set()
        for cookie in r.cookies:
            if not cookie.secure and "Missing Secure Cookie Flag" not in reported:
                reported.add("Missing Secure Cookie Flag")
                self._add("Missing Secure Cookie Flag",f"Cookie '{cookie.name}' missing Secure flag.",
                    "Cookie transmitted over plain HTTP — intercept risk.")
            if not cookie.has_nonstandard_attr("httponly") and "Missing HttpOnly Cookie Flag" not in reported:
                reported.add("Missing HttpOnly Cookie Flag")
                self._add("Missing HttpOnly Cookie Flag",f"Cookie '{cookie.name}' missing HttpOnly flag.",
                    "Cookie accessible to JavaScript — XSS-based theft possible.")
            if not cookie.has_nonstandard_attr("samesite") and "Cookie Without SameSite" not in reported:
                reported.add("Cookie Without SameSite")
                self._add("Cookie Without SameSite",f"Cookie '{cookie.name}' missing SameSite attribute.",
                    "Cookie sent on cross-origin requests — CSRF attack vector.")

    def check_cache_control(self):
        r = self._main()
        if not r: return
        cc = r.headers.get("Cache-Control","").lower()
        body_lower = r.text.lower()
        if "no-store" not in cc and "no-cache" not in cc and "private" not in cc:
            if any(k in body_lower for k in ["password","logout","account","dashboard","session","profile"]):
                self._add("Cache Control Issues",f"Cache-Control: '{cc}' on potentially sensitive page.",
                    "Sensitive page responses may be cached — private data at risk.")

    def check_directory_listing(self):
        for path in ["/images/","/uploads/","/assets/","/static/","/files/","/backup/","/data/","/tmp/"]:
            url = self.target + path
            r = safe_get(url,timeout=5)
            if r and r.status_code == 200 and ("index of" in r.text.lower() or "parent directory" in r.text.lower()):
                self._add("Directory Listing Enabled",f"Directory listing at {url}",
                    "Web server lists directory contents — internal file structures exposed.",[url])
                break

    def check_admin_panels(self):
        admin_paths = [
            "/admin","/admin/","/administrator","/wp-admin","/wp-login.php",
            "/login","/panel","/cpanel","/whm","/webmail","/manage","/management",
            "/backend","/cms","/console","/phpmyadmin","/adminer","/jenkins",
            "/grafana","/kibana","/portainer","/traefik","/vault","/rancher",
            "/solr","/mongo-express","/redis-commander","/flower","/airflow",
        ]
        for path in admin_paths:
            url = self.target + path
            r = safe_get(url,timeout=5,allow_redirects=True)
            if r and r.status_code == 200:
                if any(k in r.text.lower() for k in ["login","password","username","sign in","administration"]):
                    self._add("Admin Panel Exposed",f"Admin interface at {url}",
                        "Administrative interface publicly accessible — brute-force/credential stuffing target.",[url],severity="High")
                    break

    def check_backup_files(self):
        base = self.domain.replace(".","_").replace("-","_")
        today = datetime.date.today()
        patterns = []
        for ext in [".bak",".zip",".tar.gz",".tar",".gz",".old",".sql",".dump"]:
            patterns.extend([f"/{base}{ext}",f"/backup{ext}",f"/site{ext}",
                             f"/backup_{today.year}{today.month:02d}{ext}"])
        for path in patterns[:12]:
            url = self.target + path
            r = safe_get(url,timeout=5)
            if r and r.status_code == 200 and len(r.content) > 100:
                ct = r.headers.get("Content-Type","")
                if any(t in ct for t in ["zip","gzip","octet-stream","sql","tar"]):
                    self._add("Backup Files Accessible",f"Backup at {url} ({len(r.content)} bytes)",
                        "Archive/backup file publicly downloadable — may contain source code, credentials.",[url],severity="High")
                    break

    def check_api_exposure(self):
        api_paths = [
            "/api","/api/v1","/api/v2","/api/v3","/graphql","/rest",
            "/swagger","/swagger-ui.html","/api-docs","/openapi.json",
            "/swagger.json","/swagger.yaml","/.well-known/api-catalog",
            "/api/users","/api/user","/api/admin","/api/keys","/api/config",
        ]
        for path in api_paths:
            url = self.target + path
            r = safe_get(url,timeout=6)
            if r and r.status_code == 200:
                ct = r.headers.get("Content-Type","").lower()
                if "json" in ct or "yaml" in ct or "swagger" in r.text.lower() or "graphql" in r.text.lower():
                    self._add("API Endpoint Exposure",f"Unauthenticated API at {url}",
                        "API endpoint responds without authentication.",[url])
                    break

    def check_http_methods(self):
        try:
            r = SESSION.options(self.target,timeout=7,verify=False)
            allow = r.headers.get("Allow","")
            dangerous = [m for m in ["TRACE","TRACK","PUT","DELETE"] if m in allow.upper()]
            if dangerous:
                self._add("HTTP Methods Enabled",f"Allow: {allow}",
                    f"Dangerous HTTP methods: {', '.join(dangerous)} — may allow server manipulation.")
        except Exception:
            pass

    def check_robots(self):
        r = safe_get(self.target+"/robots.txt",timeout=6)
        if r and r.status_code == 200:
            sensitive = re.findall(r"(?i)(?:disallow|allow):\s*(/[^\n]*(?:admin|backup|config|private|secret|api|db|database|internal|staging)[^\n]*)",r.text)
            if sensitive:
                self._add("robots.txt Sensitive Disclosure",
                    f"Sensitive paths: {', '.join(sensitive[:5])}",
                    "robots.txt discloses internal paths — guides attackers to high-value targets.")

    def check_js_libraries(self):
        r = self._main()
        if not r: return
        soup = BeautifulSoup(r.text,"html.parser")
        VULN_LIBS = {
            "jquery-1.":  "jQuery 1.x — multiple XSS CVEs (CVE-2019-11358, CVE-2020-11022/23)",
            "jquery-2.":  "jQuery 2.x — EOL, CVE-2020-11022",
            "jquery-3.4": "jQuery 3.4.x — prototype pollution CVE-2019-11358",
            "angular.js": "AngularJS 1.x — EOL Dec 2021, multiple XSS vectors",
            "bootstrap-2":"Bootstrap 2.x — EOL, no security patches",
            "bootstrap-3":"Bootstrap 3.x — EOL, no security patches",
            "prototype-1":"Prototype.js — prototype pollution vulnerabilities",
        }
        hits = []
        for tag in soup.find_all("script",src=True):
            src = tag["src"].lower()
            for pattern, note in VULN_LIBS.items():
                if pattern in src:
                    hits.append(note)
        if hits:
            self._add("Outdated Libraries Detected","; ".join(hits[:3]),
                "Vulnerable JS libraries loaded — known CVEs exploitable client-side.")

    def check_sri(self):
        r = self._main()
        if not r: return
        soup = BeautifulSoup(r.text,"html.parser")
        missing = [tag.get("src") or tag.get("href") for tag in soup.find_all(["script","link"])
                   if (tag.get("src") or tag.get("href","")).startswith("http") and not tag.get("integrity")]
        if len(missing) >= 2:
            self._add("Subresource Integrity Missing",f"{len(missing)} external resource(s) lack SRI hashes.",
                "External scripts/styles without SRI hashes — CDN compromise can inject malicious code.")

    def check_open_redirect(self):
        payloads = ["?next=https://evil.com","?redirect=https://evil.com","?url=https://evil.com",
                    "?redir=https://evil.com","?return_url=https://evil.com","?goto=https://evil.com"]
        for p in payloads:
            url = self.target + p
            r = safe_get(url,allow_redirects=False,timeout=6)
            if r and r.status_code in (301,302,307,308):
                loc = r.headers.get("Location","")
                if "evil.com" in loc:
                    self._add("Open Redirect",f"Redirect to {loc} via {url}",
                        "Unvalidated redirect — phishing via trusted domain URL.",[url])
                    return

    def check_xss_indicators(self):
        r = self._main()
        if not r: return
        soup = BeautifulSoup(r.text,"html.parser")
        marker = "xss7z9qtest"
        for form in soup.find_all("form")[:3]:
            action = form.get("action") or self.target
            if not action.startswith("http"):
                action = self.target + "/" + action.lstrip("/")
            inputs = {inp.get("name"):marker for inp in form.find_all("input")
                      if inp.get("name") and inp.get("type","") not in ("submit","hidden","csrf")}
            if not inputs: continue
            try:
                resp = SESSION.post(action,data=inputs,timeout=8,verify=False)
                if marker in resp.text:
                    self._add("No Input Validation (Reflected)",f"Test value reflected from {action}",
                        "User input reflected unencoded — potential Reflected XSS.",[action],severity="High")
                    break
            except Exception:
                pass

    def check_error_disclosure(self):
        error_sigs = {
            "PHP":      ["fatal error","warning:","parse error","stack trace","on line"],
            "Python":   ["traceback","django.core","flask","wsgi","exception in"],
            "Java":     ["javax.","java.lang","at org.","struts","tomcat"],
            "ASP.NET":  ["asp.net","system.web","server error in '/' application"],
            "Database": ["sql syntax","mysql_fetch","ora-","pg::","sqlite","unclosed quotation"],
        }
        for url in [self.target+"/nonexistent-vapt-test",self.target+"/?id=1'"]:
            r = safe_get(url,timeout=6)
            if r:
                body_lower = r.text.lower()
                for tech, sigs in error_sigs.items():
                    if any(s in body_lower for s in sigs):
                        self._add("Error Message Information Leakage",
                            f"Verbose {tech} error at {url}",
                            f"Detailed {tech} errors exposed — reveals internals and potential attack vectors.",[url])
                        return

    def check_jwt(self):
        r = self._main()
        if not r: return
        jwt_pattern = r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
        all_jwts = re.findall(jwt_pattern,r.text)
        all_jwts += [c.value for c in r.cookies if re.match(jwt_pattern,c.value)]
        for token in all_jwts[:1]:
            try:
                parts = token.split(".")
                header = json.loads(base64.b64decode(parts[0] + "=="))
                alg = header.get("alg","")
                if alg.lower() in ("none",""):
                    self._add("JWT Misconfiguration",f"JWT alg=none found",
                        "JWT 'none' algorithm allows forging tokens without a signature.",severity="Critical")
                elif alg == "HS256":
                    self._add("JWT Misconfiguration",f"JWT using HS256 (symmetric) found",
                        "HS256 tokens vulnerable to brute-force if secret is weak.",severity="Medium")
            except Exception:
                pass

    def check_websocket(self):
        r = self._main()
        if not r: return
        ws = re.findall(r"ws://[^\s\"']+",r.text)
        if ws:
            self._add("WebSocket Without TLS",f"Insecure WebSocket: {ws[0]}",
                "ws:// WebSocket transmits data unencrypted — use wss:// instead.")

    def check_path_traversal(self):
        for p in ["?file=../../../../etc/passwd","?path=../../../etc/shadow","?page=....//....//etc/passwd"]:
            url = self.target + p
            r = safe_get(url,timeout=6)
            if r and ("root:" in r.text or "bin/bash" in r.text):
                self._add("Path Traversal Indicators",f"Traversal response at {url}",
                    "Directory traversal possible — OS files may be readable.",[url],severity="Critical")
                return

    def check_ssrf(self):
        for p in ["?url=http://169.254.169.254/latest/meta-data/","?webhook=http://169.254.169.254/"]:
            url = self.target + p
            r = safe_get(url,timeout=6)
            if r and any(k in r.text for k in ["ami-id","instance-id","security-credentials"]):
                self._add("SSRF Surface Detected",f"SSRF at {url} returned AWS metadata",
                    "Server fetches internal cloud metadata — SSRF confirmed.",[url],severity="Critical")
                return

    def check_default_credentials(self):
        admin_paths = ["/wp-login.php","/admin/login","/login","/admin"]
        default_creds = [("admin","admin"),("admin","password"),("admin","123456")]
        for path in admin_paths[:2]:
            url = self.target + path
            r = safe_get(url,timeout=5)
            if not r or r.status_code != 200: continue
            soup = BeautifulSoup(r.text,"html.parser")
            for form in soup.find_all("form")[:1]:
                action = form.get("action") or url
                if not action.startswith("http"):
                    action = self.target + "/" + action.lstrip("/")
                user_field = next((i.get("name") for i in form.find_all("input")
                                   if i.get("type","") in ("text","email") or "user" in (i.get("name") or "").lower()),None)
                pass_field = next((i.get("name") for i in form.find_all("input") if i.get("type")=="password"),None)
                if user_field and pass_field:
                    for user, pwd in default_creds[:2]:
                        try:
                            resp = SESSION.post(action,data={user_field:user,pass_field:pwd},
                                               timeout=8,verify=False,allow_redirects=True)
                            if resp.status_code == 200 and any(k in resp.text.lower() for k in
                               ["dashboard","logout","welcome","settings"]) and \
                               "invalid" not in resp.text.lower():
                                self._add("Default Credentials Hint",
                                    f"Login at {action} accepted {user}/{pwd}",
                                    "Default credentials accepted — immediate password change required.",[action],severity="Critical")
                                return
                        except Exception:
                            pass

    def check_dns_zone_transfer(self):
        try:
            ns_records = dns.resolver.resolve(self.domain,"NS",lifetime=5)
            for ns in ns_records:
                try:
                    ns_ip = str(dns.resolver.resolve(str(ns),"A",lifetime=4)[0])
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip,self.domain,timeout=5))
                    if zone:
                        self._add("DNS Zone Transfer Possible",
                            f"AXFR succeeded from NS {ns} ({ns_ip})",
                            "Full DNS zone exposed — all subdomains and infrastructure revealed.",severity="High")
                        return
                except Exception:
                    pass
        except Exception:
            pass

    def check_dns_email(self):
        try:
            spf_found = False
            try:
                answers = dns.resolver.resolve(self.domain,"TXT",lifetime=5)
                spf_found = any("v=spf1" in str(r) for r in answers)
            except Exception:
                pass
            if not spf_found:
                self._add("SPF Record Missing",f"No SPF TXT for {self.domain}",
                    "Without SPF, anyone can spoof email from your domain.")
            try:
                answers = dns.resolver.resolve(f"_dmarc.{self.domain}","TXT",lifetime=5)
                dmarc_found = any("v=dmarc1" in str(r).lower() for r in answers)
                if not dmarc_found:
                    self._add("DMARC Record Missing",f"No valid DMARC at _dmarc.{self.domain}",
                        "Without DMARC, email spoofing is trivial.")
            except Exception:
                self._add("DMARC Record Missing",f"_dmarc.{self.domain} returned no results",
                    "DMARC policy absent — domain vulnerable to email spoofing.")
            try:
                dns.resolver.resolve(self.domain,"DNSKEY",lifetime=5)
            except (dns.resolver.NoAnswer,dns.resolver.NXDOMAIN):
                self._add("DNSSEC Not Implemented",f"No DNSKEY for {self.domain}",
                    "DNSSEC not enabled — DNS cache poisoning risk.")
            except Exception:
                pass
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════════
    #   MASTER RUN
    # ══════════════════════════════════════════════════════════════════════

    def run(self, progress_cb=None):
        all_steps = [
            ("DNS records",           self.recon_dns),
            ("IP geolocation",        self.recon_ip_info),
            ("WHOIS registration",    self.recon_whois),
            ("SSL certificate",       self.recon_ssl_certificate),
            ("Subdomains (50+)",      self.recon_subdomains),
            ("Port scan (25 ports)",  self.recon_port_scan),
            ("Technology stack",      self.recon_technologies),
            ("WAF detection",         self.recon_waf_detection),
            ("Email harvesting",      self.recon_email_harvest),
            ("Contact & social OSINT",self.recon_contacts),
            ("Source code comments",  self.recon_source_comments),
            ("Linked pages",          self.recon_linked_pages),
            ("CT log query",          self.recon_ct_logs),
            ("Extractable files",     self.recon_extractable_files),
            ("Security headers",      self.check_security_headers),
            ("CORS policy",           self.check_cors),
            ("CORS preflight",        self.check_cors_preflight),
            ("Server disclosure",     self.check_server_disclosure),
            ("SSL/TLS redirect",      self.check_ssl),
            ("Cookies",               self.check_cookies),
            ("Cache control",         self.check_cache_control),
            ("Clickjacking",          self.check_clickjacking),
            ("Mixed content",         self.check_mixed_content),
            ("Directory listing",     self.check_directory_listing),
            ("Admin panels",          self.check_admin_panels),
            ("Backup files",          self.check_backup_files),
            ("API endpoints",         self.check_api_exposure),
            ("HTTP methods",          self.check_http_methods),
            ("robots.txt",            self.check_robots),
            ("JS libraries",          self.check_js_libraries),
            ("Subresource integrity", self.check_sri),
            ("Open redirect",         self.check_open_redirect),
            ("Input validation/XSS",  self.check_xss_indicators),
            ("Error disclosure",      self.check_error_disclosure),
            ("JWT tokens",            self.check_jwt),
            ("WebSocket security",    self.check_websocket),
            ("Path traversal",        self.check_path_traversal),
            ("SSRF surface",          self.check_ssrf),
            ("Default credentials",   self.check_default_credentials),
            ("DNS zone transfer",     self.check_dns_zone_transfer),
            ("DNS/email security",    self.check_dns_email),
        ]

        total = len(all_steps)
        print(Fore.RED + f"\n  [*] Target : {self.target}")
        print(Fore.RED +  f"  [*] Domain : {self.domain}\n")

        for idx, (label, fn) in enumerate(tqdm(all_steps, desc="  Scanning",
                              bar_format="{l_bar}"+Fore.RED+"{bar}"+Style.RESET_ALL+"{r_bar}")):
            if progress_cb:
                progress_cb(label, idx + 1, total)
            try:
                fn()
            except Exception:
                pass

        return self.findings, self.intel


# ─────────────────────────────────────────────────────────────────────────────
#  JSON EXPORT
# ─────────────────────────────────────────────────────────────────────────────

def save_results_json(target, domain, findings, intel, score_data, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] += 1

    # Build OWASP breakdown
    owasp_counts = {}
    for f in findings:
        key = f"{f['owasp_id']} {f['owasp_name']}"
        owasp_counts[key] = owasp_counts.get(key, 0) + 1

    payload = {
        "meta": {
            "tool": "Ash's VAPT & OSINT Tool v3.0",
            "target": target,
            "domain": domain,
            "scan_date": datetime.datetime.utcnow().isoformat() + "Z",
            "total_findings": len(findings),
        },
        "score": score_data,
        "severity_counts": counts,
        "owasp_breakdown": owasp_counts,
        "findings": sorted(findings, key=lambda x: SEVERITY_ORDER.index(x["severity"])),
        "intel": intel,
    }

    out_path = os.path.join(out_dir, "results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    return out_path


# ─────────────────────────────────────────────────────────────────────────────
#  CONSOLE SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(findings, intel, score_data):
    COLOR={"Critical":Fore.RED,"High":Fore.LIGHTYELLOW_EX,"Medium":Fore.YELLOW,"Low":Fore.WHITE,"Info":Fore.CYAN}
    print(Fore.RED+"\n"+"═"*65)
    print(Fore.RED+"  OSINT INTELLIGENCE SUMMARY")
    print(Fore.RED+"═"*65)
    for ip_info in intel.get("ip_info",[]):
        print(f"  {Fore.YELLOW}IP{Style.RESET_ALL}          {ip_info.get('query',ip_info.get('ip','?'))}")
        print(f"  {Fore.YELLOW}Location{Style.RESET_ALL}    {ip_info.get('city','?')}, {ip_info.get('regionName','?')}, {ip_info.get('country','?')}")
        print(f"  {Fore.YELLOW}ISP/ASN{Style.RESET_ALL}     {ip_info.get('isp','?')} | {ip_info.get('as','?')}")
    tech=intel.get("technologies",{})
    for key in ["CMS","WAF","Server","JS Frameworks","CDN","Email Provider"]:
        if tech.get(key):
            print(f"  {Fore.YELLOW}{key:<12}{Style.RESET_ALL}  {tech[key]}")
    subs=intel.get("subdomains",[])
    print(f"  {Fore.YELLOW}Subdomains{Style.RESET_ALL}   {len(subs)} discovered")
    ports=intel.get("ports",[])
    if ports:
        port_str=", ".join([f"{p['port']}/{p['service']}" for p in ports])
        print(f"  {Fore.YELLOW}Open Ports{Style.RESET_ALL}   {port_str}")
    ssl_d=intel.get("ssl",{})
    if ssl_d.get("days_until_expiry") is not None:
        days=ssl_d["days_until_expiry"]
        col=Fore.RED if days<30 else Fore.GREEN
        print(f"  {Fore.YELLOW}SSL Expiry{Style.RESET_ALL}   {col}{days} days{Style.RESET_ALL}")
    emails=intel.get("emails",[])
    if emails:
        print(f"  {Fore.YELLOW}Emails{Style.RESET_ALL}       {', '.join(emails[:3])}")
    ct=intel.get("ct_logs",[])
    print(f"  {Fore.YELLOW}CT Log Entries{Style.RESET_ALL} {len(ct)}")
    print(Fore.RED+"\n"+"═"*65)
    print(Fore.RED+f"  SECURITY SCORE: {score_data['score']}/100  Grade: {score_data['grade']}")
    print(Fore.RED+"═"*65)
    print(Fore.RED+f"  VULNERABILITY FINDINGS ({len(findings)} total)")
    print(Fore.RED+"═"*65)
    for f in sorted(findings,key=lambda x:SEVERITY_ORDER.index(x["severity"])):
        c=COLOR.get(f["severity"],Fore.WHITE)
        print(f"  {c}[{f['severity']:<8}]{Style.RESET_ALL}  {f['id']}  {f['name']}")
    print(Fore.RED+"─"*65)
    counts={s:0 for s in SEVERITY_ORDER}
    for f in findings: counts[f["severity"]] += 1
    for sev in SEVERITY_ORDER:
        if counts[sev]: print(f"  {COLOR[sev]}{sev:<12}{Style.RESET_ALL}  {counts[sev]}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
#  DASHBOARD SERVER  (with /api/scan + /api/status)
# ─────────────────────────────────────────────────────────────────────────────

def run_scan_thread(target_url, port):
    """Called in a background thread. Runs the full scan and saves results."""
    global SCAN_STATE
    try:
        target = normalise_url(target_url)
        domain = get_domain(target)

        SCAN_STATE["status"]  = "scanning"
        SCAN_STATE["target"]  = target
        SCAN_STATE["step"]    = "Initialising…"
        SCAN_STATE["progress"] = 0
        SCAN_STATE["error"]   = ""

        def progress_cb(label, current, total):
            SCAN_STATE["step"]     = label
            SCAN_STATE["current"]  = current
            SCAN_STATE["total"]    = total
            SCAN_STATE["progress"] = int((current / total) * 100)

        scanner = VAPTScanner(target)
        findings, intel = scanner.run(progress_cb=progress_cb)

        score_data = calculate_security_score(findings)
        print_summary(findings, intel, score_data)

        out_dir = f"vapt_report_{domain}_{datetime.date.today().isoformat()}"
        results_path = save_results_json(target, domain, findings, intel, score_data, out_dir)

        SCAN_STATE["status"]       = "done"
        SCAN_STATE["progress"]     = 100
        SCAN_STATE["step"]         = "Scan complete!"
        SCAN_STATE["results_path"] = results_path

    except Exception as e:
        SCAN_STATE["status"] = "error"
        SCAN_STATE["error"]  = str(e)
        print(Fore.RED + f"[!] Scan error: {e}")


def launch_server(port=8765):
    if not FLASK_AVAILABLE:
        print(Fore.RED + "[!] Flask not installed. Run: pip install flask")
        return

    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    # Serve index.html from the project root directory
    root_dir = os.path.dirname(os.path.abspath(__file__))
    app = Flask(__name__, static_folder=root_dir)

    # ── CORS helper — allow file:// and localhost origins ─────────────────────
    def _cors(response):
        origin = flask_request.headers.get("Origin", "")
        # Allow file:// (browsers send null), and any localhost origin
        if origin in ("", "null") or origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1"):
            response.headers["Access-Control-Allow-Origin"] = origin or "null"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return response
    app.after_request(_cors)

    @app.route("/")
    def index():
        return send_from_directory(root_dir, "index.html")

    # Also serve the standalone index.html directly
    @app.route("/index.html")
    def index_html():
        return send_from_directory(root_dir, "index.html")

    # Handle OPTIONS preflight for all API routes
    @app.route("/api/<path:p>", methods=["OPTIONS"])
    def options_handler(p):
        resp = app.make_default_options_response()
        return _cors(resp)

    # ── Trigger a scan ────────────────────────────────────────────────────────
    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        global SCAN_STATE
        data = flask_request.get_json(force=True)
        url  = (data.get("url") or "").strip()
        if not url:
            return jsonify({"error": "No URL provided"}), 400
        if SCAN_STATE["status"] == "scanning":
            return jsonify({"error": "Scan already in progress"}), 409
        # Reset state
        SCAN_STATE = {
            "status": "scanning", "target": url, "step": "Starting…",
            "progress": 0, "total": 0, "current": 0,
            "results_path": None, "error": "",
        }
        threading.Thread(target=run_scan_thread, args=(url, port), daemon=True).start()
        return jsonify({"ok": True})

    # ── Poll progress ─────────────────────────────────────────────────────────
    @app.route("/api/status")
    def api_status():
        return jsonify({
            "status":   SCAN_STATE["status"],
            "target":   SCAN_STATE["target"],
            "step":     SCAN_STATE["step"],
            "progress": SCAN_STATE["progress"],
            "current":  SCAN_STATE["current"],
            "total":    SCAN_STATE["total"],
            "error":    SCAN_STATE["error"],
        })

    # ── Fetch results ─────────────────────────────────────────────────────────
    @app.route("/api/results")
    def api_results():
        rp = SCAN_STATE.get("results_path")
        if not rp or not os.path.exists(rp):
            return jsonify({"error": "No results available yet"}), 404
        with open(rp, encoding="utf-8") as f:
            return jsonify(json.load(f))

    print(Fore.CYAN + f"\n  ╔══════════════════════════════════════════════════╗")
    print(Fore.CYAN + f"  ║  Backend running on http://localhost:{port}         ║")
    print(Fore.CYAN + f"  ║  Open index.html in your browser to scan          ║")
    print(Fore.CYAN + f"  ║  Press Ctrl+C to stop the server                  ║")
    print(Fore.CYAN + f"  ╚══════════════════════════════════════════════════╝\n")

    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False, threaded=True)


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    banner()
    port = 8765
    if len(sys.argv) >= 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            pass

    # If a URL is passed as argument, pre-queue it
    if len(sys.argv) >= 2:
        url = sys.argv[1].strip()
        print(Fore.YELLOW + f"  [*] Pre-queuing scan for: {url}")
        threading.Thread(target=run_scan_thread, args=(url, port), daemon=True).start()
    else:
        print(Fore.YELLOW + "  [*] No URL given — open the dashboard to enter one.")

    launch_server(port=port)


if __name__ == "__main__":
    main()
