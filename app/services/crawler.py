from collections import deque
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 WebShield-AI/2.4"
SKIP_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico', '.pdf', '.zip', '.tar', '.gz', '.mp4', '.mp3', '.css', '.js', '.woff', '.woff2', '.ttf', '.eot')

def same_host(a, b):
    try:
        netloc_a = urlparse(a).netloc.lower().split(':')[0].replace("www.", "")
        netloc_b = urlparse(b).netloc.lower().split(':')[0].replace("www.", "")
        return bool(netloc_a and netloc_b and netloc_a == netloc_b)
    except Exception:
        return False

def crawl(start_url: str, max_depth: int = 1, max_pages: int = 20):
    # Enforce realistic boundary limits based on depth
    if max_depth <= 0:
        max_pages = 1
    elif max_depth == 1:
        max_pages = min(max_pages, 10)
    else:
        max_pages = min(max_pages, 25)

    queue = deque([(start_url, 0)])
    visited = set()
    pages, forms, endpoints = [], [], []

    session = requests.Session()
    session.headers.update({
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    })

    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        
        # Normalize trailing slash for deduplication
        norm_url = url.rstrip('/')
        if norm_url in visited or depth > max_depth:
            continue
        visited.add(norm_url)

        # Skip static binary assets
        parsed = urlparse(url)
        if any(parsed.path.lower().endswith(ext) for ext in SKIP_EXTENSIONS):
            continue

        try:
            r = session.get(url, timeout=4, allow_redirects=True)
        except requests.RequestException:
            continue

        content_type = r.headers.get("content-type", "").lower()
        if "text/html" not in content_type:
            continue

        try:
            soup = BeautifulSoup(r.text, "html.parser")
        except Exception:
            continue

        page = {
            "url": url,
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "title": soup.title.get_text(strip=True) if soup.title else "",
        }
        pages.append(page)

        # Extract forms
        for form in soup.find_all("form"):
            forms.append({
                "page": url,
                "action": urljoin(url, form.get("action") or url),
                "method": (form.get("method") or "GET").upper(),
                "inputs": [x.get("name") for x in form.find_all(["input", "textarea", "select"]) if x.get("name")]
            })

        # Extract hyperlinks
        if depth < max_depth:
            for link in soup.find_all("a", href=True):
                href = link.get("href", "").strip()
                if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                    continue
                nxt = urljoin(url, href).split("#")[0]
                if same_host(start_url, nxt):
                    endpoints.append(nxt)
                    if nxt.rstrip('/') not in visited:
                        queue.append((nxt, depth + 1))

    return {
        "pages": pages,
        "forms": forms,
        "endpoints": sorted(set(endpoints))
    }
