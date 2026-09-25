def passive_scan(crawl_result):
    """
    Passive website security checks.
    Inspects response headers, HTML forms, and discovered endpoints
    for common OWASP Top 10 weaknesses.
    """
    findings = []

    for page in crawl_result.get("pages", []):
        headers = {k.lower(): v for k, v in page.get("headers", {}).items()}
        url = page["url"]

        # 1. Content Security Policy (A05 / A03)
        if "content-security-policy" not in headers:
            findings.append({
                "type": "Missing Content-Security-Policy",
                "url": url,
                "severity": "Medium",
                "owasp_category": "A05: Security Misconfiguration",
                "description": "The website does not restrict where scripts and content can be loaded from.",
                "evidence": "Missing Content-Security-Policy response header."
            })

        # 2. X-Content-Type-Options (A05)
        if "x-content-type-options" not in headers:
            findings.append({
                "type": "Missing MIME Protection (X-Content-Type-Options)",
                "url": url,
                "severity": "Low",
                "owasp_category": "A05: Security Misconfiguration",
                "description": "Browsers may be tricked into running disguised files as scripts.",
                "evidence": "Missing X-Content-Type-Options: nosniff header."
            })

        # 3. Clickjacking Protection / X-Frame-Options (A05)
        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            findings.append({
                "type": "Missing Clickjacking Protection (X-Frame-Options)",
                "url": url,
                "severity": "Medium",
                "owasp_category": "A05: Security Misconfiguration",
                "description": "Other websites can embed this page inside an invisible frame to trick users into clicking buttons.",
                "evidence": "Missing X-Frame-Options response header."
            })

        # 4. HSTS (A05 / A02)
        if "strict-transport-security" not in headers and url.startswith("https://"):
            findings.append({
                "type": "Missing Secure HTTPS Rule (HSTS)",
                "url": url,
                "severity": "Medium",
                "owasp_category": "A05: Security Misconfiguration",
                "description": "Visitors are not automatically forced to stay on the encrypted HTTPS version.",
                "evidence": "Missing Strict-Transport-Security response header on HTTPS route."
            })

        # 5. Server Technology Leakage (A05 / A06)
        server = headers.get("server")
        if server:
            findings.append({
                "type": "Exposed Server Version",
                "url": url,
                "severity": "Low",
                "owasp_category": "A05: Security Misconfiguration",
                "description": f"The website reveals its web server software ({server}), helping attackers find targeted loopholes.",
                "evidence": f"Server: {server}"
            })

        # 6. Technology Framework Exposure (A05 / A06)
        x_powered = headers.get("x-powered-by")
        if x_powered:
            findings.append({
                "type": "Exposed Technology Framework (X-Powered-By)",
                "url": url,
                "severity": "Low",
                "owasp_category": "A05: Security Misconfiguration",
                "description": f"The website reveals its application framework ({x_powered}).",
                "evidence": f"X-Powered-By: {x_powered}"
            })

        # 7. Missing Referrer-Policy (A05)
        if "referrer-policy" not in headers:
            findings.append({
                "type": "Missing Referrer-Policy",
                "url": url,
                "severity": "Low",
                "owasp_category": "A05: Security Misconfiguration",
                "description": "The browser may leak sensitive URL parameters to third-party links clicked by users.",
                "evidence": "Missing Referrer-Policy response header."
            })

        # 8. Missing Permissions-Policy (A05)
        if "permissions-policy" not in headers:
            findings.append({
                "type": "Missing Permissions-Policy",
                "url": url,
                "severity": "Low",
                "owasp_category": "A05: Security Misconfiguration",
                "description": "The site does not restrict browser hardware features like camera, microphone, or geolocation.",
                "evidence": "Missing Permissions-Policy response header."
            })

        # 9. Insecure Cookie Flags (A02 / A07)
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            sc_lower = set_cookie.lower()
            if "httponly" not in sc_lower:
                findings.append({
                    "type": "Cookie Missing HttpOnly Flag",
                    "url": url,
                    "severity": "Medium",
                    "owasp_category": "A07: Identification and Authentication Failures",
                    "description": "Session cookies can be read by JavaScript, making them vulnerable to theft via Cross-Site Scripting (XSS).",
                    "evidence": "Set-Cookie header missing HttpOnly flag."
                })
            if "secure" not in sc_lower and url.startswith("https://"):
                findings.append({
                    "type": "Cookie Missing Secure Flag",
                    "url": url,
                    "severity": "Medium",
                    "owasp_category": "A02: Cryptographic Failures",
                    "description": "Cookies can be sent over unencrypted HTTP connections in cleartext.",
                    "evidence": "Set-Cookie header missing Secure flag on HTTPS connection."
                })

    # 10. Form Security Checks (A01 & A02 & A07)
    for form in crawl_result.get("forms", []):
        action = form.get("action", "")
        method = (form.get("method") or "GET").upper()
        inputs = [str(x).lower() for x in form.get("inputs", []) if x]

        # Insecure HTTP transmission
        if action.startswith("http://"):
            findings.append({
                "type": "Unencrypted Form Submission",
                "url": action,
                "severity": "High",
                "owasp_category": "A02: Cryptographic Failures",
                "description": "This form sends submitted data across unencrypted HTTP, allowing passwords and info to be intercepted.",
                "evidence": f"Form action target: {action}"
            })

        # Sensitive password field over HTTP
        has_password = any("pass" in inp or "pwd" in inp for inp in inputs)
        if has_password and (action.startswith("http://") or form.get("page", "").startswith("http://")):
            findings.append({
                "type": "Password Transmitted Over Insecure Channel",
                "url": form.get("page", action),
                "severity": "High",
                "owasp_category": "A07: Identification and Authentication Failures",
                "description": "A password input field is delivered or submitted over plain HTTP without encryption.",
                "evidence": f"Form inputs include password fields over unencrypted channel."
            })

        # State-changing POST form without anti-CSRF token
        if method == "POST":
            has_csrf = any("csrf" in inp or "token" in inp or "xsrf" in inp for inp in inputs)
            if not has_csrf and len(inputs) > 0:
                findings.append({
                    "type": "Form Missing CSRF Protection",
                    "url": form.get("page", action),
                    "severity": "Medium",
                    "owasp_category": "A01: Broken Access Control",
                    "description": "This form accepts POST data without an anti-CSRF protection token, which may allow unauthorized requests.",
                    "evidence": f"Form at {form.get('page', action)} with inputs: {', '.join(inputs[:4])}"
                })

    # 11. Sensitive Administrative Endpoints Exposed (A01)
    admin_keywords = ("/admin", "/wp-admin", "/login", "/dashboard", "/cpanel", "/phpmyadmin", "/portal")
    for ep in crawl_result.get("endpoints", []):
        ep_lower = ep.lower()
        if any(kw in ep_lower for kw in admin_keywords):
            findings.append({
                "type": "Exposed Login or Administrative Link",
                "url": ep,
                "severity": "Low",
                "owasp_category": "A01: Broken Access Control",
                "description": "A direct link to an administrative login or control panel was discovered publicly on the website.",
                "evidence": f"Discovered link: {ep}"
            })
            break # Flag once to avoid cluttering

    # 12. Potential Open Directory / Backup Exposure (A05)
    sensitive_extensions = (".bak", ".sql", ".env", ".git", ".zip", ".tar.gz")
    for ep in crawl_result.get("endpoints", []):
        ep_lower = ep.lower()
        if any(ep_lower.endswith(ext) for ext in sensitive_extensions):
            findings.append({
                "type": "Exposed Sensitive Backup File",
                "url": ep,
                "severity": "High",
                "owasp_category": "A05: Security Misconfiguration",
                "description": "A potential backup or configuration archive file is directly linked or accessible.",
                "evidence": f"Discovered sensitive file link: {ep}"
            })
            break

    return findings
