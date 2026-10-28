from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl, Field
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

from app.services.verifier import verify_target, clean_url
from app.services.crawler import crawl
from app.services.scanner import passive_scan
from app.services.analyzer import analyze_findings
from app.services.reporter import generate_pdf_report
from app.services.ai_service import ask_ai_assistant
from app.database import (
    create_user,
    authenticate_user,
    create_user_session,
    get_user_by_token,
    revoke_session,
    get_guest_quota,
    record_scan_usage,
    reset_guest_quotas,
    reset_quota_for_identifier,
    GUEST_SCAN_LIMIT
)

app = FastAPI(title="WebShield AI - Security Advisor & Vulnerability Scanner", version="2.0.0")

REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "frontend")), name="static")

class ScanRequest(BaseModel):
    target_url: str
    crawl_depth: int = Field(default=1, ge=0, le=2)
    scan_speed: str = Field(default="Balanced")
    report_format: str = Field(default="PDF")
    authorized: bool = False
    utm_source: str = ""
    utm_medium: str = ""
    utm_campaign: str = ""


class AIAskRequest(BaseModel):
    question: str
    finding_type: str = ""
    context: str = ""
    api_key: str = ""


class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str = ""
    utm_source: str = ""
    utm_medium: str = ""
    utm_campaign: str = ""


class ContactRequest(BaseModel):
    name: str = ""
    email: str
    subject: str = "General Inquiry"
    message: str
    target_url: str = ""
    utm_source: str = ""
    utm_medium: str = ""


class LoginRequest(BaseModel):
    email: str
    password: str


def get_auth_context(request: Request):
    """Extract authenticated user and guest identifier from request."""
    auth_header = request.headers.get("authorization", "")
    token = ""
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    if not token:
        token = request.headers.get("x-auth-token", "")
    if not token:
        token = request.cookies.get("webshield_session", "")

    user = get_user_by_token(token) if token else None

    client_ip = request.client.host if request.client else "127.0.0.1"
    guest_id_header = request.headers.get("x-guest-id", "").strip()
    identifier = guest_id_header if guest_id_header else client_ip

    return user, identifier, token


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


@app.get("/login", response_class=HTMLResponse)
def login_page():
    response = FileResponse(BASE_DIR / "frontend" / "login.html")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    return response


@app.get("/register", response_class=HTMLResponse)
def register_page():
    response = FileResponse(BASE_DIR / "frontend" / "register.html")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    return response


@app.get("/privacy", response_class=HTMLResponse)
def privacy_page():
    response = FileResponse(BASE_DIR / "frontend" / "privacy.html")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    return response


@app.get("/terms", response_class=HTMLResponse)
def terms_page():
    response = FileResponse(BASE_DIR / "frontend" / "terms.html")
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    return response


@app.get("/favicon.svg")
def favicon():
    return FileResponse(BASE_DIR / "frontend" / "favicon.svg", media_type="image/svg+xml")


@app.get("/favicon.ico")
def favicon_ico():
    return FileResponse(BASE_DIR / "frontend" / "favicon.svg", media_type="image/svg+xml")



# =====================================================================
# Authentication Endpoints
# =====================================================================

@app.post("/api/auth/register")
def register(req: RegisterRequest):
    user, err = create_user(email=req.email, password=req.password, name=req.name)
    if not user:
        return {"success": False, "message": err}

    token = create_user_session(user.id)
    return {
        "success": True,
        "token": token,
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "scan_count": user.scan_count
        }
    }


@app.post("/api/auth/login")
def login(req: LoginRequest):
    user = authenticate_user(email=req.email, password=req.password)
    if not user:
        return {"success": False, "message": "Invalid email or password."}

    token = create_user_session(user.id)
    return {
        "success": True,
        "token": token,
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "scan_count": user.scan_count
        }
    }


@app.post("/api/auth/logout")
def logout(request: Request):
    _, _, token = get_auth_context(request)
    if token:
        revoke_session(token)
    return {"success": True}


@app.get("/api/auth/status")
def auth_status(request: Request):
    user, identifier, _ = get_auth_context(request)
    if user:
        return {
            "authenticated": True,
            "user": {
                "id": user.id,
                "email": user.email,
                "name": user.name,
                "scan_count": user.scan_count
            },
            "quota": {
                "is_unlimited": True,
                "used": user.scan_count,
                "remaining": "unlimited",
                "can_scan": True
            }
        }
    else:
        quota = get_guest_quota(identifier)
        return {
            "authenticated": False,
            "user": None,
            "quota": quota
        }


@app.post("/api/contact")
def submit_contact(req: ContactRequest):
    if not req.email or "@" not in req.email:
        return {"success": False, "message": "Please provide a valid email address."}
    if not req.message or len(req.message.strip()) < 5:
        return {"success": False, "message": "Please include a message with at least 5 characters."}

    import uuid
    ref_id = f"WSAI-{uuid.uuid4().hex[:8].upper()}"
    contact_log = BASE_DIR / "reports" / "contact_inquiries.log"
    try:
        with open(contact_log, "a", encoding="utf-8") as f:
            f.write(f"[{ref_id}] From: {req.name} <{req.email}> | Subject: {req.subject} | URL: {req.target_url} | UTM: {req.utm_source}/{req.utm_medium} | Message: {req.message}\n")
    except Exception:
        pass

    return {
        "success": True,
        "reference_id": ref_id,
        "message": f"Inquiry submitted successfully. Your reference ID is {ref_id}."
    }


@app.post("/api/auth/reset-quota")
def reset_guest_quota_api(request: Request):
    """Reset free scan credits for guest user so refreshing starts clean."""
    user, identifier, _ = get_auth_context(request)
    if not user:
        reset_quota_for_identifier(identifier)
        return {
            "success": True,
            "quota": get_guest_quota(identifier)
        }
    return {
        "success": True,
        "is_unlimited": True,
        "message": "User is authenticated with unlimited scans"
    }


# =====================================================================
# Core Scanner Endpoints with Quota Verification
# =====================================================================

@app.post("/api/verify")
def verify(req: ScanRequest):
    if not req.authorized:
        return {
            "valid": False,
            "error": "Please check the box confirming you have permission to test this website."
        }
    return verify_target(clean_url(req.target_url))


@app.post("/api/scan")
def run_scan(req: ScanRequest, request: Request):
    user, identifier, _ = get_auth_context(request)

    # Enforce scan limit for non-authenticated guests
    if not user:
        quota = get_guest_quota(identifier)
        if not quota["can_scan"]:
            return {
                "status": "error",
                "error_code": "SCAN_LIMIT_REACHED",
                "limit_reached": True,
                "quota": quota,
                "message": "Your free credits are over! Please sign in or register for free unlimited scans."
            }

    if not req.authorized:
        return {"status": "error", "message": "Only test websites that you own or have permission to test."}

    target = clean_url(req.target_url)
    verification = verify_target(target)
    if not verification["valid"]:
        return {
            "status": "error",
            "stage": "verification",
            "verification": verification,
            "message": verification.get("message", "Could not reach this website.")
        }

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

    # Record scan usage and update quota
    updated_quota = record_scan_usage(
        identifier=identifier,
        user=user,
        target_url=target,
        vuln_count=len(analyzed)
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
        "report": f"/reports/{report_path.name}",
        "quota": updated_quota
    }


@app.post("/api/ai/ask")
def ai_assistant(req: AIAskRequest):
    return ask_ai_assistant(
        question=req.question,
        context=req.context,
        finding_type=req.finding_type,
        client_api_key=req.api_key
    )


@app.get("/reports/{filename}")
def download_report(filename: str):
    path = REPORT_DIR / filename
    if not path.exists():
        return {"error": "Report not found"}
    return FileResponse(path, media_type="application/pdf", filename=filename)