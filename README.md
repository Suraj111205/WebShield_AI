# WebShield AI - Security Advisor & Vulnerability Scanner

A friendly, easy-to-use website vulnerability scanner and security advisor that helps you find website weaknesses, discover pages and forms, and fix issues with simple guidance.

This implementation follows the supplied security pipeline:

**Start → User → Target Input → Website Verification → BFS Crawler Engine → Passive Scanning Engine → AI Analysis & CVSS Engine → Reporting & Output → End.**

---

## Vulnerabilities Checked (Total: 15 Automated Checks across 10 OWASP Categories)

WebShield AI checks for vulnerabilities across **10 OWASP Top 10 categories**:

| # | Vulnerability Check | OWASP Category | Scan Level | Severity |
|---|---|---|---|---|
| 1 | **Missing Content-Security-Policy (CSP)** | A05 / A03 | Basic, Med, Deep | Medium |
| 2 | **Missing MIME Protection (X-Content-Type-Options)** | A05 | Basic, Med, Deep | Low |
| 3 | **Missing Clickjacking Protection (X-Frame-Options)** | A05 / A04 | Basic, Med, Deep | Medium |
| 4 | **Missing Strict-Transport-Security (HSTS)** | A05 / A02 | Basic, Med, Deep | Medium |
| 5 | **Exposed Web Server Version Banner** | A05 / A06 | Basic, Med, Deep | Low |
| 6 | **Exposed Technology Framework (X-Powered-By)** | A05 / A06 | Basic, Med, Deep | Low |
| 7 | **Missing Referrer-Policy** | A05 | Basic, Med, Deep | Low |
| 8 | **Missing Permissions-Policy** | A05 | Basic, Med, Deep | Low |
| 9 | **Cookie Missing HttpOnly Flag** | A07 / A03 | Deep | Medium |
| 10 | **Cookie Missing Secure Flag** | A02 | Deep | Medium |
| 11 | **Unencrypted HTTP Form Submission** | A02 | Medium, Deep | High |
| 12 | **Password Transmitted Over Insecure Channel** | A07 / A02 | Medium, Deep | High |
| 13 | **Form Missing Anti-CSRF Protection Token** | A01 | Medium, Deep | Medium |
| 14 | **Exposed Login or Administrative Link (/admin, /login)** | A01 | Medium, Deep | Low |
| 15 | **Exposed Sensitive Backup File (.env, .git, .bak)** | A05 | Deep | High |

---

## Scanning Levels

1. **Basic Scan (Free - Quick Surface Check):**
   - **Scope:** Homepage only (Depth 0).
   - **Speed:** 2 to 5 seconds.
   - **Checks:** SSL/TLS certificate validity, HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Server version banners.

2. **Medium Scan (Recommended - Interactive & Form Checks):**
   - **Scope:** Level-1 BFS Queue crawl (Homepage + direct links up to 10 pages).
   - **Speed:** 10 to 20 seconds.
   - **Checks:** Everything in Basic Scan + unencrypted HTTP form submissions, password inputs over insecure channels, missing anti-CSRF tokens on POST forms, exposed administrative endpoints (`/admin`, `/login`).

3. **Deep Scan (Most Thorough - Deep Architecture & File Audit):**
   - **Scope:** Multi-level BFS Queue crawl (Depth 2, up to 25 linked pages).
   - **Speed:** 30 to 60 seconds.
   - **Checks:** Everything in Basic & Medium scans + cookie security flags (`HttpOnly`, `Secure`), exposed backup files (`.bak`, `.sql`, `.env`), subresource integrity, and full downloadable executive PDF report.

---

## Methods & Algorithms Used

1. **Breadth-First Search (BFS) Web Crawler:**
   - Employs a `collections.deque` FIFO queue to traverse site links level-by-level (depth 0 $\rightarrow$ depth 1 $\rightarrow$ depth 2).
   - Domain normalization and an $O(1)$ `visited` set to prevent infinite crawl loops and duplicate requests.
   - Connection pooling with `requests.Session()` and HTTP Keep-Alive for rapid scanning.
2. **Heuristic HTTP Header Inspection:**
   - Evaluates response headers against RFC security specifications (RFC 6797, RFC 7034, W3C CSP Level 3).
3. **DOM Form & Parameter Extraction (BeautifulSoup4):**
   - Parses HTML DOM trees to extract `<form>` actions, HTTP methods (`GET` vs `POST`), and `<input>` security attributes.
4. **CVSS v3.1 Scoring Algorithm:**
   - Quantifies risk scores (Low: 0.1–3.9, Medium: 4.0–6.9, High: 7.0–8.9, Critical: 9.0–10.0) based on exploitability and impact.

---

## Run locally

1. Install Python 3.12 or later.
2. Open a terminal in this folder.
3. Activate virtual environment:
   ```powershell
   .\venv\Scripts\Activate.ps1
   ```
4. Start the server:
   ```bash
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```
5. Open in browser: `http://127.0.0.1:8000`

---

## Custom Domain Deployment Guide

To connect a custom domain (e.g. `scanner.yourdomain.com` or `webshieldai.com`) for production launch:

### 1. DNS Configuration
In your DNS provider (Cloudflare, Namecheap, GoDaddy, Route 53):
- **A Record:** Point `@` or your subdomain to your server's Public IPv4 address.
- **CNAME Record (if using PaaS like Render/Railway):** Point your subdomain to the PaaS domain target provided in the dashboard.

### 2. Nginx Reverse Proxy Configuration (Production VPS / Linux Server)
Create `/etc/nginx/sites-available/webshield`:
```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
Enable the site and obtain SSL via Let's Encrypt:
```bash
sudo ln -s /etc/nginx/sites-available/webshield /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

### 3. Running as a System Service (systemd)
Create `/etc/systemd/system/webshield.service`:
```ini
[Unit]
Description=WebShield AI Defense System
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/path/to/autonomous-cyber-defense-system
ExecStart=/path/to/autonomous-cyber-defense-system/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 4
Restart=always

[Install]
WantedBy=multi-user.target
```
Start and enable the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable webshield
sudo systemctl start webshield
```
