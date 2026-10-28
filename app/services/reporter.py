import os
from pathlib import Path
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, PageBreak
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

BASE_DIR = Path(__file__).resolve().parent.parent.parent
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Theme Colors Matching WebShield AI & OWASP Standard
# ---------------------------------------------------------------------------
COLOR_BRAND_DARK     = colors.HexColor("#0A0E17")  # Deep Cyber Midnight
COLOR_BRAND_SURFACE  = colors.HexColor("#111827")  # Dark Surface Panel
COLOR_BRAND_CYAN     = colors.HexColor("#00E5FF")  # Neon Cyan Accent
COLOR_BRAND_PURPLE   = colors.HexColor("#7C4DFF")  # OWASP Violet
COLOR_TEXT_PRIMARY   = colors.HexColor("#0F172A")  # Slate 900 for print readability
COLOR_TEXT_MUTED     = colors.HexColor("#475569")  # Slate 600
COLOR_TEXT_LIGHT     = colors.HexColor("#F8FAFC")  # Crisp White
COLOR_BORDER         = colors.HexColor("#CBD5E1")  # Slate 300 border
COLOR_BORDER_SUBTLE  = colors.HexColor("#E2E8F0")  # Slate 200
COLOR_BG_CARD        = colors.HexColor("#F8FAFC")  # Very Light Slate
COLOR_CODE_BG        = colors.HexColor("#0D1117")  # Dark Code Block
COLOR_CODE_TEXT      = colors.HexColor("#00E5FF")  # Neon Cyan Code Font

# Severity Colors
SEV_CRITICAL_BG = colors.HexColor("#7F1D1D")
SEV_CRITICAL_TEXT = colors.HexColor("#FEE2E2")
SEV_HIGH_BG     = colors.HexColor("#DC2626")
SEV_HIGH_TEXT   = colors.HexColor("#FEF2F2")
SEV_MED_BG      = colors.HexColor("#D97706")
SEV_MED_TEXT    = colors.HexColor("#FFFBEB")
SEV_LOW_BG      = colors.HexColor("#059669")
SEV_LOW_TEXT    = colors.HexColor("#ECFDF5")
SEV_INFO_BG     = colors.HexColor("#0284C7")
SEV_INFO_TEXT   = colors.HexColor("#F0F9FF")

# ---------------------------------------------------------------------------
# Comprehensive Dual-Audience Knowledge Base
# (Technical Mechanics + Plain English for Students/Beginners + Code Snippets)
# ---------------------------------------------------------------------------
VULN_EXPLANATIONS = {
    "Missing Content-Security-Policy": {
        "beginner": (
            "<b>What this means in simple words:</b><br/>"
            "Think of Content-Security-Policy (CSP) like a security guard at your website's door with a VIP guest list. "
            "Without CSP, the browser will run any code it finds on the page. If a hacker manages to inject a malicious script "
            "(called Cross-Site Scripting or XSS), the browser executes it without question, which can steal user passwords or session cookies."
        ),
        "technical": (
            "<b>Technical Impact & Root Cause:</b><br/>"
            "The HTTP response lacks a <code>Content-Security-Policy</code> header (W3C Recommendation). "
            "In the absence of a strict CSP directive, the user-agent defaults to permissive resource loading, allowing execution of inline scripts, "
            "untrusted third-party domains, and arbitrary object embeds. This drastically increases vulnerability to Reflected, Stored, and DOM XSS."
        ),
        "remediation_code": (
            "<b>Recommended Server Remediation:</b><br/>"
            "<b>Nginx:</b><br/>"
            "<code>add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none';\" always;</code><br/>"
            "<b>Apache:</b><br/>"
            "<code>Header set Content-Security-Policy \"default-src 'self'; script-src 'self';\"</code>"
        )
    },
    "Missing MIME Protection (X-Content-Type-Options)": {
        "beginner": (
            "<b>What this means in simple words:</b><br/>"
            "Web browsers sometimes try to be 'too smart' by guessing what kind of file something is. "
            "If an attacker uploads an image that secretly hides computer code, a confused browser might run it like an executable program. "
            "Adding this protection tells the browser: 'Never guess file types - trust only the official header.'"
        ),
        "technical": (
            "<b>Technical Impact & Root Cause:</b><br/>"
            "The <code>X-Content-Type-Options: nosniff</code> header is missing. When absent, certain browsers execute MIME-type sniffing on HTTP responses, "
            "potentially treating non-executable MIME types (e.g., <code>text/plain</code> or image uploads) as executable JavaScript (MIME confusion attack)."
        ),
        "remediation_code": (
            "<b>Recommended Server Remediation:</b><br/>"
            "<b>Nginx:</b> <code>add_header X-Content-Type-Options \"nosniff\" always;</code><br/>"
            "<b>Apache:</b> <code>Header always set X-Content-Type-Options \"nosniff\"</code>"
        )
    },
    "Missing Clickjacking Protection (X-Frame-Options)": {
        "beginner": (
            "<b>What this means in simple words:</b><br/>"
            "Clickjacking is like placing an invisible transparent sheet over a computer screen. "
            "A malicious website can load your website inside an invisible iframe and trick a user into clicking 'Transfer Funds' or 'Delete Account' "
            "while they think they are clicking a harmless button like 'Play Game'."
        ),
        "technical": (
            "<b>Technical Impact & Root Cause:</b><br/>"
            "Missing <code>X-Frame-Options</code> (RFC 7034) or CSP <code>frame-ancestors</code> directive. "
            "The website permits cross-origin iframe framing, allowing adversaries to mount UI Redress / Clickjacking attacks to hijack authenticated user clicks."
        ),
        "remediation_code": (
            "<b>Recommended Server Remediation:</b><br/>"
            "<b>Nginx:</b> <code>add_header X-Frame-Options \"SAMEORIGIN\" always;</code><br/>"
            "<b>Apache:</b> <code>Header always append X-Frame-Options SAMEORIGIN</code>"
        )
    },
    "Missing Secure HTTPS Rule (HSTS)": {
        "beginner": (
            "<b>What this means in simple words:</b><br/>"
            "Even if your website supports the secure HTTPS padlock, without HSTS an attacker on the same public Wi-Fi "
            "can silently intercept visitors and downgrade their connection to unencrypted plain HTTP. "
            "HSTS tells all browsers: 'Always use encrypted HTTPS - never talk to me over plain HTTP.'"
        ),
        "technical": (
            "<b>Technical Impact & Root Cause:</b><br/>"
            "Missing <code>Strict-Transport-Security</code> response header (RFC 6797). "
            "Exposes user connections to SSL Stripping and Man-in-the-Middle (MitM) eavesdropping during the initial HTTP redirection phase."
        ),
        "remediation_code": (
            "<b>Recommended Server Remediation:</b><br/>"
            "<b>Nginx:</b> <code>add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;</code><br/>"
            "<b>Apache:</b> <code>Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"</code>"
        )
    },
    "Exposed Server Version": {
        "beginner": (
            "<b>What this means in simple words:</b><br/>"
            "Your web server is announcing its exact software name and version number (for example, Apache 2.4.41). "
            "This is like hanging a sign outside your office saying what brand of locks you use. "
            "Automated hacker bots look for these numbers to find known, unpatched exploits."
        ),
        "technical": (
            "<b>Technical Impact & Root Cause:</b><br/>"
            "Information leakage via <code>Server</code> HTTP banner. "
            "Simplifies reconnaissance for automated threat actors by revealing exact software build numbers and potential unpatched CVE targets."
        ),
        "remediation_code": (
            "<b>Recommended Server Remediation:</b><br/>"
            "<b>Nginx:</b> Set <code>server_tokens off;</code> in <code>/etc/nginx/nginx.conf</code>.<br/>"
            "<b>Apache:</b> Set <code>ServerTokens Prod</code> and <code>ServerSignature Off</code> in configuration."
        )
    },
    "Exposed Technology Framework (X-Powered-By)": {
        "beginner": (
            "<b>What this means in simple words:</b><br/>"
            "The website is telling visitors what programming technology was used to build it (such as PHP or Express). "
            "Hiding this information makes it much harder for attackers to launch targeted attacks against your system."
        ),
        "technical": (
            "<b>Technical Impact & Root Cause:</b><br/>"
            "Information disclosure via <code>X-Powered-By</code> header. "
            "Discloses application runtime stack, reducing attacker search space when staging targeted framework vulnerabilities."
        ),
        "remediation_code": (
            "<b>Recommended Server Remediation:</b><br/>"
            "<b>Express.js:</b> <code>app.disable('x-powered-by');</code><br/>"
            "<b>PHP:</b> Set <code>expose_php = Off</code> in <code>php.ini</code>."
        )
    },
    "Missing Referrer-Policy": {
        "beginner": (
            "<b>What this means in simple words:</b><br/>"
            "When users click on an external link on your site, their browser automatically shares the full URL of the page they just came from. "
            "If your web address includes sensitive information (like user IDs or reset tokens), that private data leaks to outside websites."
        ),
        "technical": (
            "<b>Technical Impact & Root Cause:</b><br/>"
            "Missing <code>Referrer-Policy</code> header. "
            "Browsers may leak sensitive URL parameters, query strings, and session identifiers in the <code>Referer</code> request header during cross-origin navigations."
        ),
        "remediation_code": (
            "<b>Recommended Server Remediation:</b><br/>"
            "<b>Nginx:</b> <code>add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;</code><br/>"
            "<b>Apache:</b> <code>Header set Referrer-Policy \"strict-origin-when-cross-origin\"</code>"
        )
    },
    "Missing Permissions-Policy": {
        "beginner": (
            "<b>What this means in simple words:</b><br/>"
            "Your website hasn't told the browser which physical device features are forbidden. "
            "This protection ensures that unauthorized third-party scripts or ads can never activate sensitive hardware like webcams, microphones, or GPS."
        ),
        "technical": (
            "<b>Technical Impact & Root Cause:</b><br/>"
            "Missing <code>Permissions-Policy</code> header (formerly Feature-Policy). "
            "Fails to enforce least privilege on sensitive browser APIs (camera, microphone, geolocation, payment request)."
        ),
        "remediation_code": (
            "<b>Recommended Server Remediation:</b><br/>"
            "<code>add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;</code>"
        )
    },
    "Cookie Missing HttpOnly Flag": {
        "beginner": (
            "<b>What this means in simple words:</b><br/>"
            "When you log into a website, you are given a digital access badge called a cookie. "
            "Without the HttpOnly tag, any JavaScript code running on the page can read and steal your badge, allowing a hacker to take over your account."
        ),
        "technical": (
            "<b>Technical Impact & Root Cause:</b><br/>"
            "<code>Set-Cookie</code> header lacks the <code>HttpOnly</code> attribute (RFC 6265). "
            "The session token is accessible via JavaScript <code>document.cookie</code>, leaving authenticated sessions vulnerable to theft via Cross-Site Scripting (XSS)."
        ),
        "remediation_code": (
            "<b>Recommended Remediation:</b><br/>"
            "Ensure session cookies specify <code>HttpOnly</code> attribute when issued:<br/>"
            "<code>Set-Cookie: session_id=xyz; Path=/; HttpOnly; Secure; SameSite=Lax</code>"
        )
    },
    "Cookie Missing Secure Flag": {
        "beginner": (
            "<b>What this means in simple words:</b><br/>"
            "Without the Secure tag, your browser is allowed to transmit your login cookie across plain, unencrypted HTTP. "
            "Anyone eavesdropping on the same network (e.g. coffee shop Wi-Fi) can see your login badge in clear text."
        ),
        "technical": (
            "<b>Technical Impact & Root Cause:</b><br/>"
            "<code>Set-Cookie</code> header lacks the <code>Secure</code> flag (RFC 6265). "
            "Enables transmission of sensitive session tokens over unencrypted HTTP channels during accidental cleartext requests."
        ),
        "remediation_code": (
            "<b>Recommended Remediation:</b><br/>"
            "Configure backend framework or server to append the <code>Secure</code> flag on all cookie headers:<br/>"
            "<code>Set-Cookie: token=xyz; Secure; HttpOnly; SameSite=Strict</code>"
        )
    },
    "Unencrypted Form Submission": {
        "beginner": (
            "<b>What this means in simple words:</b><br/>"
            "This web form sends submitted information across plain, unencrypted 'http://'. "
            "It is like mailing a postcard with personal secrets written on the back for anyone along the way to read, instead of using a sealed envelope."
        ),
        "technical": (
            "<b>Technical Impact & Root Cause:</b><br/>"
            "HTML <code>&lt;form&gt;</code> element <code>action</code> attribute points to an insecure <code>http://</code> endpoint. "
            "Transmitted credentials and sensitive parameters are sent in cleartext, vulnerable to packet capture and Man-in-the-Middle inspection."
        ),
        "remediation_code": (
            "<b>Recommended HTML Remediation:</b><br/>"
            "Update form target to encrypted HTTPS:<br/>"
            "<code>&lt;form action=\"https://yourdomain.com/api/submit\" method=\"POST\"&gt;</code>"
        )
    },
    "Password Transmitted Over Insecure Channel": {
        "beginner": (
            "<b>What this means in simple words:</b><br/>"
            "A login or password box was found on an unencrypted page or sends passwords without encryption. "
            "Anyone monitoring the network can intercept and read the password directly."
        ),
        "technical": (
            "<b>Technical Impact & Root Cause:</b><br/>"
            "Password input field (<code>&lt;input type=\"password\"&gt;</code>) delivered or submitted over unencrypted HTTP. "
            "Violates NIST SP 800-63B authentication guidelines and OWASP A07."
        ),
        "remediation_code": (
            "<b>Recommended Remediation:</b><br/>"
            "Enforce universal HTTPS redirection and ensure authentication endpoints are strictly delivered and received over TLS."
        )
    },
    "Form Missing CSRF Protection": {
        "beginner": (
            "<b>What this means in simple words:</b><br/>"
            "Cross-Site Request Forgery (CSRF) is like a fraudster tricking your bank into sending money while you are already logged in. "
            "An anti-CSRF token is a secret one-time password inside the form that proves the real user actually clicked the button."
        ),
        "technical": (
            "<b>Technical Impact & Root Cause:</b><br/>"
            "State-changing HTTP <code>POST</code> form lacks an anti-CSRF challenge token. "
            "Enables adversaries to forge unauthorized state-changing requests executed by authenticated victim browsers."
        ),
        "remediation_code": (
            "<b>Recommended Remediation:</b><br/>"
            "Embed an unpredictable cryptographically secure anti-CSRF token in the form:<br/>"
            "<code>&lt;input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token }}\"/&gt;</code>"
        )
    },
    "Exposed Login or Administrative Link": {
        "beginner": (
            "<b>What this means in simple words:</b><br/>"
            "A direct link to an administrative login portal (such as /admin or /cpanel) is publicly visible. "
            "This gives automated attacker bots an obvious target to try password-guessing and brute-force attacks."
        ),
        "technical": (
            "<b>Technical Impact & Root Cause:</b><br/>"
            "Administrative interfaces discovered in public DOM anchors. "
            "Expands attack surface by advertising sensitive control plane access points to unauthenticated visitors."
        ),
        "remediation_code": (
            "<b>Recommended Remediation:</b><br/>"
            "Remove administrative routes from public navigation bars and protect them with IP access control lists and Multi-Factor Authentication (MFA)."
        )
    },
    "Exposed Sensitive Backup File": {
        "beginner": (
            "<b>What this means in simple words:</b><br/>"
            "Backup files or secret configuration archives (like .env or .sql) are directly accessible online. "
            "Anyone can download these files to view database passwords, API secret keys, and confidential data."
        ),
        "technical": (
            "<b>Technical Impact & Root Cause:</b><br/>"
            "Sensitive configuration archives (<code>.env</code>, <code>.git</code>, <code>.bak</code>, <code>.sql</code>) accessible over web root. "
            "Results in critical exposure of database credentials and API secrets."
        ),
        "remediation_code": (
            "<b>Recommended Server Remediation:</b><br/>"
            "<b>Nginx:</b> <code>location ~ /\\.(env|git|bak|sql|zip)$ { deny all; return 404; }</code>"
        )
    }
}

# ---------------------------------------------------------------------------
# Numbered Canvas for Running Headers, Footers, and Page Numbers
# ---------------------------------------------------------------------------
class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(36, 810, "OWASP TOP 10 SECURITY AUDIT & VULNERABILITY ASSESSMENT REPORT")
            self.drawRightString(559, 810, "WEBSHIELD AI")
            self.setStrokeColor(colors.HexColor("#00E5FF"))
            self.setLineWidth(1)
            self.line(36, 804, 559, 804)

        # Running Footer (all pages)
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(36, 32, 559, 32)
        
        self.drawString(36, 20, "CONFIDENTIAL • Generated by WebShield AI Autonomous Cyber Defense System • OWASP Standards")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(559, 20, page_str)
        self.restoreState()


# ---------------------------------------------------------------------------
# Main PDF Generator Function
# ---------------------------------------------------------------------------
def generate_pdf_report(target, verification, crawl_result, findings):
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    date_display = datetime.now().strftime("%d %B %Y, %H:%M:%S UTC")
    filename = f"owasp_scan_report_{timestamp_str}.pdf"
    path = REPORT_DIR / filename

    # Page setup: A4 with 36pt (0.5 inch) side margins
    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=46,
        bottomMargin=42
    )

    # Styles
    sample_styles = getSampleStyleSheet()

    styles = {
        "Title": ParagraphStyle(
            "DocTitle",
            parent=sample_styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=COLOR_BRAND_CYAN,
            alignment=0,
            spaceAfter=4
        ),
        "Subtitle": ParagraphStyle(
            "DocSubtitle",
            parent=sample_styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#94A3B8"),
            alignment=0,
            spaceAfter=10
        ),
        "SectionHeading": ParagraphStyle(
            "SectionHeading",
            parent=sample_styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=COLOR_BRAND_DARK,
            spaceBefore=14,
            spaceAfter=6,
            keepWithNext=True
        ),
        "Body": ParagraphStyle(
            "BodyRegular",
            parent=sample_styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=COLOR_TEXT_PRIMARY
        ),
        "BodyMuted": ParagraphStyle(
            "BodyMuted",
            parent=sample_styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=COLOR_TEXT_MUTED
        ),
        "CardTitle": ParagraphStyle(
            "CardTitle",
            parent=sample_styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=COLOR_BRAND_DARK
        ),
        "BadgeText": ParagraphStyle(
            "BadgeText",
            parent=sample_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9,
            alignment=1
        ),
        "Code": ParagraphStyle(
            "CodeBlock",
            parent=sample_styles["Code"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=COLOR_TEXT_PRIMARY
        )
    }

    story = []

    # -----------------------------------------------------------------------
    # 1. Header Banner (Cyber Dark Theme with Cyan Neon & Violet Accents)
    # -----------------------------------------------------------------------
    banner_content = [
        [
            Paragraph("WEBSHIELD AI // AUTONOMOUS CYBER DEFENSE", ParagraphStyle("BannerTag", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=COLOR_BRAND_CYAN)),
            Paragraph(f"AUDIT REF: WSH-{timestamp_str[:8]}", ParagraphStyle("BannerRef", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=colors.HexColor("#94A3B8"), alignment=2))
        ],
        [
            Paragraph("OWASP Top 10 Security Assessment Report", styles["Title"]),
            Paragraph("CONFIDENTIAL ASSESSMENT", ParagraphStyle("ConfBadge", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=colors.HexColor("#F87171"), alignment=2))
        ],
        [
            Paragraph(
                "Automated Dynamic Application Security Testing (DAST) • Vulnerability Audit • Remediation Advisory",
                styles["Subtitle"]
            ),
            ""
        ]
    ]

    banner_table = Table(banner_content, colWidths=[380, 143])
    banner_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), COLOR_BRAND_DARK),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("SPAN", (0, 2), (1, 2)),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 10))

    # -----------------------------------------------------------------------
    # 2. Assessment Metadata Table
    # -----------------------------------------------------------------------
    meta_data = [
        [
            Paragraph("<b>Target Domain:</b>", styles["Body"]),
            Paragraph(f"<code>{target}</code>", styles["Body"]),
            Paragraph("<b>Assessment Date:</b>", styles["Body"]),
            Paragraph(date_display, styles["Body"])
        ],
        [
            Paragraph("<b>Target Status:</b>", styles["Body"]),
            Paragraph(f"{verification.get('message', 'Reachable')}", styles["Body"]),
            Paragraph("<b>Security Standard:</b>", styles["Body"]),
            Paragraph("OWASP Top 10 (2021/2025) & CVSS v3.1", styles["Body"])
        ],
        [
            Paragraph("<b>Pages Audited:</b>", styles["Body"]),
            Paragraph(f"{len(crawl_result.get('pages', []))} page(s)", styles["Body"]),
            Paragraph("<b>Interactive Forms:</b>", styles["Body"]),
            Paragraph(f"{len(crawl_result.get('forms', []))} form(s)", styles["Body"])
        ]
    ]

    meta_table = Table(meta_data, colWidths=[95, 170, 105, 153])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
        ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_SUBTLE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # -----------------------------------------------------------------------
    # 3. Executive Summary & Security Posture Breakdown
    # -----------------------------------------------------------------------
    story.append(Paragraph("1. Executive Summary & Risk Posture", styles["SectionHeading"]))

    crit_count = sum(1 for f in findings if f.get("severity") == "Critical")
    high_count = sum(1 for f in findings if f.get("severity") == "High")
    med_count  = sum(1 for f in findings if f.get("severity") == "Medium")
    low_count  = sum(1 for f in findings if f.get("severity") == "Low")
    total_findings = len(findings)

    # Calculate overall security posture grade
    if crit_count > 0 or high_count >= 2:
        posture_grade = "D (High Risk - Immediate Remediation Required)"
        posture_color = colors.HexColor("#DC2626")
    elif high_count == 1 or med_count >= 3:
        posture_grade = "C (Moderate Risk - Action Recommended)"
        posture_color = colors.HexColor("#D97706")
    elif med_count > 0 or low_count >= 3:
        posture_grade = "B (Low-Medium Risk - Defensive Hardening Needed)"
        posture_color = colors.HexColor("#2563EB")
    elif low_count > 0:
        posture_grade = "A- (Good Posture - Minor Improvements)"
        posture_color = colors.HexColor("#059669")
    else:
        posture_grade = "A+ (Excellent Posture - No Surface Flaws Found)"
        posture_color = colors.HexColor("#059669")

    exec_summary_text = (
        f"WebShield AI completed a non-intrusive automated security audit against <b>{target}</b>. "
        f"A total of <b>{total_findings} security finding(s)</b> were identified across the surveyed application attack surface. "
        f"The evaluated overall security posture rating is <b>{posture_grade}</b>. "
        f"This report provides dual-perspective documentation: technical root-cause analyses for security engineers, "
        f"alongside plain-English conceptual explanations for students and non-technical stakeholders."
    )
    story.append(Paragraph(exec_summary_text, styles["Body"]))
    story.append(Spacer(1, 8))

    # Severity Summary Metrics Box
    metric_headers = [
        Paragraph("<b>Total Issues</b>", styles["BadgeText"]),
        Paragraph("<b>Critical</b>", styles["BadgeText"]),
        Paragraph("<b>High</b>", styles["BadgeText"]),
        Paragraph("<b>Medium</b>", styles["BadgeText"]),
        Paragraph("<b>Low</b>", styles["BadgeText"]),
    ]
    metric_values = [
        Paragraph(f"<b>{total_findings}</b>", ParagraphStyle("M1", fontName="Helvetica-Bold", fontSize=14, leading=16, alignment=1, textColor=COLOR_BRAND_DARK)),
        Paragraph(f"<b>{crit_count}</b>", ParagraphStyle("M2", fontName="Helvetica-Bold", fontSize=14, leading=16, alignment=1, textColor=SEV_HIGH_BG)),
        Paragraph(f"<b>{high_count}</b>", ParagraphStyle("M3", fontName="Helvetica-Bold", fontSize=14, leading=16, alignment=1, textColor=SEV_HIGH_BG)),
        Paragraph(f"<b>{med_count}</b>", ParagraphStyle("M4", fontName="Helvetica-Bold", fontSize=14, leading=16, alignment=1, textColor=SEV_MED_BG)),
        Paragraph(f"<b>{low_count}</b>", ParagraphStyle("M5", fontName="Helvetica-Bold", fontSize=14, leading=16, alignment=1, textColor=SEV_LOW_BG)),
    ]

    metrics_table = Table([metric_headers, metric_values], colWidths=[104, 104, 104, 104, 107])
    metrics_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_SUBTLE),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(metrics_table)
    story.append(Spacer(1, 14))

    # -----------------------------------------------------------------------
    # 4. OWASP Top 10 Coverage Matrix Table
    # -----------------------------------------------------------------------
    story.append(Paragraph("2. OWASP Top 10 (2021) Compliance Matrix", styles["SectionHeading"]))
    story.append(Paragraph(
        "The following table maps findings against official OWASP Top 10 vulnerability categories. "
        "Categories flagged with weaknesses require mitigation to achieve security compliance.",
        styles["BodyMuted"]
    ))
    story.append(Spacer(1, 6))

    owasp_matrix_data = [
        [
            Paragraph("<b>OWASP Category</b>", styles["BadgeText"]),
            Paragraph("<b>Vulnerability Domain</b>", styles["BadgeText"]),
            Paragraph("<b>Audit Status</b>", styles["BadgeText"]),
            Paragraph("<b>Identified Flaws</b>", styles["BadgeText"])
        ]
    ]

    owasp_categories_def = [
        ("A01:2021", "Broken Access Control", ("A01",)),
        ("A02:2021", "Cryptographic Failures", ("A02",)),
        ("A03:2021", "Injection (SQLi / XSS)", ("A03",)),
        ("A04:2021", "Insecure Design", ("A04",)),
        ("A05:2021", "Security Misconfiguration", ("A05",)),
        ("A06:2021", "Vulnerable & Outdated Components", ("A06",)),
        ("A07:2021", "Identification & Authentication Failures", ("A07",)),
        ("A08:2021", "Software & Data Integrity Failures", ("A08",)),
        ("A09:2021", "Security Logging & Monitoring Failures", ("A09",)),
        ("A10:2021", "Server-Side Request Forgery (SSRF)", ("A10",)),
    ]

    for code, title, prefixes in owasp_categories_def:
        matching = [f for f in findings if any(p in f.get("owasp_category", "") for p in prefixes)]
        if matching:
            status_p = Paragraph(f"<font color='#DC2626'><b>Vulnerable ({len(matching)})</b></font>", styles["Body"])
            flaws_str = ", ".join([f["type"] for f in matching][:2])
            if len(matching) > 2:
                flaws_str += f" +{len(matching)-2} more"
            flaws_p = Paragraph(flaws_str, styles["BodyMuted"])
        else:
            status_p = Paragraph("<font color='#059669'><b>Pass / No Flaws</b></font>", styles["Body"])
            flaws_p = Paragraph("No passive anomalies detected", styles["BodyMuted"])

        owasp_matrix_data.append([
            Paragraph(f"<b>{code}</b>", styles["Body"]),
            Paragraph(title, styles["Body"]),
            status_p,
            flaws_p
        ])

    owasp_table = Table(owasp_matrix_data, colWidths=[75, 175, 110, 163])
    owasp_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_BRAND_DARK),
        ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_TEXT_LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_SUBTLE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F8FAFC")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(owasp_table)
    story.append(Spacer(1, 14))

    # -----------------------------------------------------------------------
    # 5. Detailed Vulnerability Findings (Dual-Audience Format)
    # -----------------------------------------------------------------------
    story.append(Paragraph("3. Detailed Vulnerability Findings & Remediation Guide", styles["SectionHeading"]))
    story.append(Paragraph(
        "Each discovered issue is presented with dual explanations: intuitive concepts for students and beginners, "
        "followed by exact technical mechanisms, CVSS scores, and ready-to-copy code fixes for developers.",
        styles["BodyMuted"]
    ))
    story.append(Spacer(1, 10))

    if not findings:
        clean_box = [
            [Paragraph("<b>No Vulnerabilities Detected!</b>", styles["CardTitle"])],
            [Paragraph("The scanned pages satisfied all 15 automated OWASP baseline security header and form checks.", styles["Body"])]
        ]
        clean_table = Table(clean_box, colWidths=[523])
        clean_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#ECFDF5")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#059669")),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(clean_table)
    else:
        for idx, finding in enumerate(findings, 1):
            vuln_type = finding.get("type", "Unknown Vulnerability")
            sev = finding.get("severity", "Medium")
            cvss = finding.get("cvss_score", 5.0)
            owasp_cat = finding.get("owasp_category", "A05: Security Misconfiguration")
            affected_url = finding.get("url", target)

            # Colors according to severity
            if sev in ("Critical", "High"):
                badge_bg = SEV_HIGH_BG
                badge_txt = SEV_HIGH_TEXT
            elif sev == "Medium":
                badge_bg = SEV_MED_BG
                badge_txt = SEV_MED_TEXT
            else:
                badge_bg = SEV_LOW_BG
                badge_txt = SEV_LOW_TEXT

            # Lookup dual-audience explanations
            expl = VULN_EXPLANATIONS.get(vuln_type, {
                "beginner": f"<b>What this means in simple words:</b><br/>{finding.get('description', '')}",
                "technical": f"<b>Technical Details:</b><br/>{finding.get('description', '')}<br/>Evidence: {finding.get('evidence', '')}",
                "remediation_code": f"<b>Recommended Remediation:</b><br/>{finding.get('recommendation', '')}"
            })

            # Finding Header Bar
            header_row = [
                Paragraph(f"<b>FINDING #{idx:02d}: {vuln_type.upper()}</b>", ParagraphStyle("FTitle", fontName="Helvetica-Bold", fontSize=9, leading=11, textColor=COLOR_BRAND_CYAN)),
                Paragraph(f"<b>SEVERITY: {sev.upper()} | CVSS v3.1: {cvss}</b>", ParagraphStyle("FSev", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=badge_txt, alignment=2))
            ]
            header_table = Table([header_row], colWidths=[350, 173])
            header_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), COLOR_BRAND_DARK),
                ("BACKGROUND", (1, 0), (1, 0), badge_bg),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))

            # Detail Box
            card_rows = [
                [Paragraph(f"<b>OWASP Category:</b> {owasp_cat}", styles["Body"]), Paragraph(f"<b>Target URL:</b> <code>{affected_url[:55]}</code>", styles["BodyMuted"])],
                [Paragraph(expl["beginner"], styles["Body"]), ""],
                [Paragraph(expl["technical"], styles["Body"]), ""],
                [Paragraph(expl["remediation_code"], styles["Code"]), ""]
            ]

            card_table = Table(card_rows, colWidths=[260, 263])
            card_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFFFFF")),
                ("SPAN", (0, 1), (1, 1)),
                ("SPAN", (0, 2), (1, 2)),
                ("SPAN", (0, 3), (1, 3)),
                ("BACKGROUND", (0, 1), (1, 1), colors.HexColor("#F0FDF4")),  # Light Mint for Beginner
                ("BACKGROUND", (0, 2), (1, 2), colors.HexColor("#F8FAFC")),  # Slate for Technical
                ("BACKGROUND", (0, 3), (1, 3), colors.HexColor("#F1F5F9")),  # Code box
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_SUBTLE),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))

            # Keep individual vulnerability card together
            story.append(KeepTogether([header_table, card_table, Spacer(1, 10)]))

    # -----------------------------------------------------------------------
    # 6. Methodology, Disclaimer & Auditor Sign-Off
    # -----------------------------------------------------------------------
    story.append(Spacer(1, 10))
    closing_notes = [
        Paragraph("4. Assessment Methodology & Ethical Disclosure", styles["SectionHeading"]),
        Paragraph(
            "<b>Methodology:</b> WebShield AI employs a non-destructive, passive dynamic security testing engine (DAST). "
            "Internal page trees are traversed level-by-level using Breadth-First Search (BFS) with domain boundary isolation. "
            "HTTP response headers, HTML DOM form elements, and cookie directives are inspected against RFC specifications and the OWASP Top 10 framework.<br/>"
            "<b>Disclaimer:</b> Automated scanners highlight potential weaknesses based on observable response attributes. "
            "Findings should be reviewed by qualified security analysts prior to production configuration changes. "
            "Testing was executed strictly within authorized non-intrusive boundaries.",
            styles["BodyMuted"]
        ),
        Spacer(1, 14),
        Table([
            [
                Paragraph("<b>Lead Security Auditor:</b><br/>WebShield AI Automated Engine", styles["Body"]),
                Paragraph("<b>Reviewed By:</b><br/>___________________________", styles["Body"]),
                Paragraph("<b>Verification Signature:</b><br/>___________________________", styles["Body"])
            ]
        ], colWidths=[174, 174, 175], style=[
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_SUBTLE),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ])
    ]
    story.append(KeepTogether(closing_notes))

    # Build document using the NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    return path
