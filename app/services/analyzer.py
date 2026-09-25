SEVERITY_SCORE = {
    "Critical": 9.5,
    "High": 8.0,
    "Medium": 5.5,
    "Low": 2.5,
    "Info": 0.0
}

RECOMMENDATIONS = {
    "Missing Content-Security-Policy": "Add a Content-Security-Policy (CSP) header in your web server settings (e.g. `default-src 'self'`) to block unauthorized scripts and protect against XSS.",
    "Missing MIME Protection (X-Content-Type-Options)": "Add `X-Content-Type-Options: nosniff` in your web server headers so browsers don't execute downloaded files as scripts.",
    "Missing Clickjacking Protection (X-Frame-Options)": "Add `X-Frame-Options: SAMEORIGIN` or use CSP `frame-ancestors 'self'` to stop malicious sites from embedding your pages inside invisible frames.",
    "Missing Secure HTTPS Rule (HSTS)": "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to force all browsers to use encrypted HTTPS connections.",
    "Exposed Server Version": "Configure your web server to hide version numbers (e.g., in Nginx set `server_tokens off;`, in Apache set `ServerTokens Prod`).",
    "Exposed Technology Framework (X-Powered-By)": "Disable the `X-Powered-By` header in your backend framework (e.g. `app.disable('x-powered-by')` in Express or `expose_php = Off` in php.ini).",
    "Missing Referrer-Policy": "Add `Referrer-Policy: strict-origin-when-cross-origin` to prevent sensitive URL parameters from leaking to external websites.",
    "Missing Permissions-Policy": "Add `Permissions-Policy: camera=(), microphone=(), geolocation=()` to restrict access to sensitive device hardware.",
    "Cookie Missing HttpOnly Flag": "Set the `HttpOnly` flag on all session cookies so JavaScript cannot read them, preventing session hijacking.",
    "Cookie Missing Secure Flag": "Set the `Secure` flag on all cookies so they are only transmitted over encrypted HTTPS connections.",
    "Unencrypted Form Submission": "Change the form `action` URL attribute to use `https://` instead of `http://` to ensure submitted data is securely encrypted.",
    "Password Transmitted Over Insecure Channel": "Always deliver authentication forms and submit passwords over HTTPS to prevent password sniffing.",
    "Form Missing CSRF Protection": "Add a unique anti-CSRF token (hidden field) to this POST form and validate it on the server before processing changes.",
    "Exposed Login or Administrative Link": "Ensure administrative interfaces require strong authentication, Multi-Factor Authentication (MFA), and are not linked publicly in the main navigation.",
    "Exposed Sensitive Backup File": "Remove backup files (.bak, .sql, .env, .zip) from your web root and block access to dotfiles in your web server configuration."
}

def analyze_findings(findings):
    analyzed = []
    for f in findings:
        item = dict(f)
        item["cvss_score"] = SEVERITY_SCORE.get(item["severity"], 0.0)
        item["recommendation"] = RECOMMENDATIONS.get(
            item["type"],
            "Review this configuration and follow modern web security best practices."
        )
        analyzed.append(item)
    return analyzed
