import requests
from urllib.parse import urlparse

def clean_url(url: str) -> str:
    url = url.strip()
    while url.startswith("https://https://") or url.startswith("http://https://") or url.startswith("https://http://") or url.startswith("http://http://"):
        url = url.replace("https://https://", "https://").replace("http://https://", "https://").replace("https://http://", "https://").replace("http://http://", "http://")
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url


def verify_target(url: str):
    url = clean_url(url)
    result = {
        "valid": False,
        "url": url,
        "scheme": None,
        "status_code": None,
        "reachable": False,
        "https": False,
        "message": ""
    }

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        result["message"] = "Invalid HTTP/HTTPS URL format."
        return result

    result["scheme"] = parsed.scheme
    result["https"] = parsed.scheme == "https"

    try:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 WebShield-AI/2.4"
        })
        r = session.get(url, timeout=7, allow_redirects=True)
        result["status_code"] = r.status_code
        result["reachable"] = True
        result["valid"] = r.status_code < 500
        result["message"] = f"Target is reachable (HTTP {r.status_code})." if result["valid"] else f"Target returned server error {r.status_code}."
    except requests.RequestException as exc:
        # If https fails, try http fallback
        if url.startswith("https://"):
            http_fallback = "http://" + url[8:]
            try:
                r = requests.get(http_fallback, timeout=6, allow_redirects=True, headers={"User-Agent": "WebShield-AI/2.4"})
                result["url"] = http_fallback
                result["status_code"] = r.status_code
                result["reachable"] = True
                result["https"] = False
                result["valid"] = r.status_code < 500
                result["message"] = f"Target reachable over HTTP (HTTP {r.status_code})."
                return result
            except requests.RequestException:
                pass
        result["message"] = f"Target is unreachable: {str(exc).split(':')[-1].strip()}"

    return result
