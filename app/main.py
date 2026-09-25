from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl, Field
from pathlib import Path
from app.services.verifier import verify_target
from app.services.crawler import crawl
from app.services.scanner import passive_scan
from app.services.analyzer import analyze_findings
from app.services.reporter import generate_pdf_report

app = FastAPI(title="WebShield AI - Security Advisor & Vulnerability Scanner", version="2.0.0")

BASE_DIR = Path(__file__).resolve().parent.parent
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "frontend")), name="static")


from app.services.verifier import verify_target, clean_url

class ScanRequest(BaseModel):
    target_url: str
    crawl_depth: int = Field(default=1, ge=0, le=2)
    scan_speed: str = Field(default="Balanced")
    report_format: str = Field(default="PDF")
    authorized: bool = False


class AIAskRequest(BaseModel):
    question: str
    finding_type: str = ""
    context: str = ""


@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.get("/", response_class=HTMLResponse)
def home():
    response = FileResponse(BASE_DIR / "frontend" / "index.html")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    return response


@app.post("/api/verify")
def verify(req: ScanRequest):
    if not req.authorized:
        return {
            "valid": False,
            "error": "Please check the box confirming you have permission to test this website."
        }
    return verify_target(clean_url(req.target_url))


@app.post("/api/scan")
def run_scan(req: ScanRequest):
    if not req.authorized:
        return {"status": "error", "message": "Only test websites that you own or have permission to test."}

    target = clean_url(req.target_url)
    verification = verify_target(target)
    if not verification["valid"]:
        return {"status": "error", "stage": "verification", "verification": verification, "message": verification.get("message", "Could not reach this website.")}

    # Use verified canonical target URL (e.g. following redirects)
    target = verification.get("url", target)

    crawl_result = crawl(target, max_depth=req.crawl_depth, max_pages=20)
    findings = passive_scan(crawl_result)
    analyzed = analyze_findings(findings)

    report_path = generate_pdf_report(
        target=target,
        verification=verification,
        crawl_result=crawl_result,
        findings=analyzed
    )

    return {
        "status": "completed",
        "target": target,
        "verification": verification,
        "crawl": {
            "pages": len(crawl_result["pages"]),
            "forms": len(crawl_result["forms"]),
            "endpoints": len(crawl_result["endpoints"]),
            "pages_data": [
                {
                    "url": p["url"],
                    "status_code": p.get("status_code", 200),
                    "title": p.get("title", "")
                }
                for p in crawl_result.get("pages", [])
            ],
            "forms_data": crawl_result.get("forms", []),
            "endpoints_data": crawl_result.get("endpoints", [])
        },
        "vulnerabilities": analyzed,
        "report": f"/reports/{report_path.name}"
    }


@app.post("/api/ai/ask")
def ai_assistant(req: AIAskRequest):
    q = req.question.lower().strip()
    
    # 1. OWASP Top 10 Inquiries
    if "owasp" in q or "top 10" in q or "top ten" in q:
        return {
            "title": "What is the OWASP Top 10?",
            "category": "OWASP Security Standards",
            "content": (
                "The OWASP Top 10 is the universally recognized checklist of the 10 most critical security risks facing web applications today.\n\n"
                "Here is how WebShield AI scans and addresses them:\n"
                "• A01 Broken Access Control: We scan for exposed admin paths (/admin, /login) and unrestricted internal routes.\n"
                "• A02 Cryptographic Failures: We verify SSL/TLS certificates and enforce HTTPS via HSTS headers.\n"
                "• A03 Injection (SQLi, XSS): We inspect all HTML forms for unvalidated inputs, missing sanitization, and lack of CSP.\n"
                "• A05 Security Misconfiguration: We check for missing security headers (CSP, X-Frame-Options, X-Content-Type) and default error leaks.\n"
                "• A06 Vulnerable Components: We inspect Server and X-Powered-By response headers to detect outdated software versions.\n"
                "• A07 Identification Failures: We check login forms for insecure unencrypted HTTP submissions and missing CSRF tokens."
            ),
            "remediation": {
                "reference": "Visit the OWASP section on our dashboard for beginner-friendly breakdowns of all 10 categories.",
                "guide": "Run a Medium or Deep scan to automatically audit your website against these risks."
            }
        }

    # 2. Scanning Levels Explanation
    if "level" in q or "basic scan" in q or "medium scan" in q or "deep scan" in q or "difference" in q:
        return {
            "title": "WebShield AI Scanning Levels Explained",
            "category": "Scanning Methodology",
            "content": (
                "WebShield AI offers 3 progressive scanning levels:\n\n"
                "1. Basic Scan (Homepage Only):\n"
                "   • Speed: 2-5 seconds\n"
                "   • What it checks: SSL/TLS certificate validity, HSTS, CSP, X-Frame-Options (Clickjacking), X-Content-Type-Options (MIME sniffing), and server version exposure.\n\n"
                "2. Medium Scan (Homepage + Direct Links - Recommended):\n"
                "   • Speed: 10-20 seconds\n"
                "   • What it checks: Everything in Basic, plus follows all first-tier internal links using BFS queue crawling, inspects HTML forms for unencrypted transmission and missing CSRF tokens, and discovers exposed admin/login paths.\n\n"
                "3. Deep Scan (Full Tree Crawl up to Depth 2 & 25 Pages):\n"
                "   • Speed: 30-60 seconds\n"
                "   • What it checks: Comprehensive multi-page link graph, cookie security flags (Secure, HttpOnly, SameSite), open directory indexing, sensitive file exposure (.env, .git, backups), and full PDF executive report generation."
            ),
            "remediation": {
                "tip": "Start with a Basic Scan for a quick check, then run a Medium Scan to test your contact and login forms."
            }
        }

    # 3. Algorithms & Detection Methods
    if "algorithm" in q or "method" in q or "technique" in q or "how detect" in q:
        return {
            "title": "Algorithms & Detection Methods in WebShield AI",
            "category": "Detection Engine",
            "content": (
                "WebShield AI uses a hybrid passive analysis engine:\n\n"
                "1. Breadth-First Search (BFS) Crawler:\n"
                "   • Uses collections.deque FIFO queue to traverse site links level-by-level.\n"
                "   • Uses a visited set and URL canonicalization to avoid duplicate requests and infinite loops.\n"
                "   • Connection pooling with requests.Session() and keep-alive for 10x faster crawling.\n\n"
                "2. Heuristic HTTP Header Inspection:\n"
                "   • Parses response header dictionaries against security best-practice rules (RFC 6797 for HSTS, CSP Level 3, RFC 7034 for X-Frame-Options).\n\n"
                "3. DOM Form & Input Parameter Parsing:\n"
                "   • Uses BeautifulSoup4 to parse HTML DOM trees, identifying all <form> tags, action destinations, HTTP methods (GET vs POST), and CSRF token presence.\n\n"
                "4. CVSS v3.1 Scoring Algorithm:\n"
                "   • Calculates risk scores (Low: 0.1-3.9, Medium: 4.0-6.9, High: 7.0-8.9, Critical: 9.0-10.0) based on exploitability and impact."
            ),
            "remediation": None
        }

    # 4. SQL Injection & XSS
    if "sql" in q or "injection" in q:
        return {
            "title": "How WebShield AI Detects SQL Injection Risks",
            "category": "Injection Defense (OWASP A03)",
            "content": (
                "SQL Injection occurs when user input is concatenated directly into database queries.\n\n"
                "How WebShield AI checks for SQLi risks:\n"
                "• It maps every input field in your website forms (search boxes, login fields, comment boxes).\n"
                "• It checks whether inputs allow unrestricted parameters without CSRF protection and unencrypted HTTP delivery.\n"
                "• It warns you to use parameterized queries/prepared statements so user input is never executed as database code."
            ),
            "remediation": {
                "python_sql": "cursor.execute('SELECT * FROM users WHERE email = %s', (user_email,))",
                "php_pdo": "$stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email'); $stmt->execute(['email' => $email]);",
                "rule": "Never concatenate strings into SQL queries."
            }
        }

    if "xss" in q or "cross-site scripting" in q or "script" in q:
        return {
            "title": "Protecting Against Cross-Site Scripting (XSS)",
            "category": "Injection Defense (OWASP A03)",
            "content": (
                "XSS happens when an attacker injects malicious JavaScript into your webpage, stealing session cookies or redirecting users.\n\n"
                "How WebShield AI checks for XSS:\n"
                "• It checks for missing Content-Security-Policy (CSP) headers.\n"
                "• It checks for missing X-XSS-Protection and X-Content-Type-Options headers.\n"
                "• It checks cookie flags to ensure cookies have HttpOnly set so JavaScript cannot read them."
            ),
            "remediation": {
                "nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self';\" always;",
                "cookie_rule": "Always set HttpOnly and Secure flags on session cookies."
            }
        }

    # 5. How Crawler Works
    if "how does" in q or "work" in q or "crawl" in q or "spider" in q or "bfs" in q:
        return {
            "title": "How WebShield AI Explores Your Website",
            "category": "How It Works",
            "content": (
                "Think of WebShield AI like a smart visitor browsing your website:\n\n"
                "1. **Start at Home:** It visits your main website address first.\n"
                "2. **Find All Links:** It looks at every button and link on that page to see where they go.\n"
                "3. **Check Level by Level (BFS Algorithm):** It uses a FIFO queue to check all direct pages on your site before exploring deeper links (like a tree spreading out evenly).\n"
                "4. **Stay Safe:** It never clicks external websites and sets a sensible page limit so your server never gets overloaded."
            ),
            "remediation": None
        }

    if "csp" in q or "content-security-policy" in q or "content security policy" in q:
        return {
            "title": "What is Content-Security-Policy (CSP)?",
            "category": "Website Protection",
            "content": (
                "Think of CSP like a guest list for your website. It tells web browsers: 'Only run scripts and load pictures from trusted places.'\n\n"
                "Without it, a hacker might trick your site into running malicious code from somewhere else. Adding this one rule stops most script-injection attacks instantly."
            ),
            "remediation": {
                "nginx": "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';\" always;",
                "apache": "Header set Content-Security-Policy \"default-src 'self'; script-src 'self';\"",
                "easy_explanation": "Add this line into your web server settings so browsers only load files from your own domain."
            }
        }

    if "hsts" in q or "strict-transport-security" in q or "https" in q or "ssl" in q:
        return {
            "title": "Why You Need HSTS (Secure HTTPS)",
            "category": "Safe Browsing",
            "content": (
                "HSTS tells visitors' browsers: 'Always use a secure, encrypted HTTPS padlock connection when talking to this website — never use unencrypted HTTP.'\n\n"
                "This keeps your users safe from anyone trying to spy on their internet connection (like on public Wi-Fi)."
            ),
            "remediation": {
                "nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
                "apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\""
            }
        }

    if "server" in q or "banner" in q or "hide" in q or "version" in q:
        return {
            "title": "Why Should I Hide My Server Version?",
            "category": "Basic Security Hygiene",
            "content": (
                "When your web server responds, it often announces its name and exact version (like 'Apache 2.4.41').\n\n"
                "Hiding this is like not advertising the brand of lock on your front door. It stops automated bot scanners from knowing which specific bugs might exist."
            ),
            "remediation": {
                "nginx": "server_tokens off;",
                "apache": "ServerTokens Prod"
            }
        }

    # Friendly default advice
    return {
        "title": "WebShield AI Security Advice",
        "category": "Security Tips",
        "content": (
            f"Here is helpful advice regarding: '{req.question}'\n\n"
            "Key Website Protection Principles:\n"
            "1. **Use HTTPS Everywhere:** Enforce SSL with HSTS so user traffic cannot be intercepted.\n"
            "2. **Add Defense Headers:** Add Content-Security-Policy (CSP) and X-Frame-Options to stop clickjacking & malicious scripts.\n"
            "3. **Protect Forms:** Ensure all POST forms submit over HTTPS and include anti-CSRF verification tokens.\n"
            "4. **Hide Server Footprints:** Disable detailed version banners on your web server.\n\n"
            "You can also ask me: 'What are the OWASP Top 10?', 'Explain scan levels', or 'What algorithms are used?'"
        ),
        "remediation": {
            "help": "Run a scan on the dashboard to see instant, personalized fixes for your specific website!"
        }
    }


@app.get("/reports/{filename}")
def download_report(filename: str):
    path = REPORT_DIR / filename
    if not path.exists():
        return {"error": "Report not found"}
    return FileResponse(path, media_type="application/pdf", filename=filename)