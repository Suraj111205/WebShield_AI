import os
import requests
import json
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Load .env first, fallback to .env.example
if (BASE_DIR / ".env").exists():
    load_dotenv(BASE_DIR / ".env")
elif (BASE_DIR / ".env.example").exists():
    load_dotenv(BASE_DIR / ".env.example")

SYSTEM_INSTRUCTION = (
    "You are WebShield AI, an intelligent, empathetic, and expert cybersecurity mentor and security advisor for an "
    "autonomous website vulnerability scanner and defense system.\n\n"
    "Core Guidelines:\n"
    "- Converse with the user naturally, conversationally, and interactively like a friendly professor or cybersecurity expert.\n"
    "- Always provide complete, thorough, and well-explained answers. Never cut off or truncate your explanations.\n"
    "- For students and beginners, explain complex concepts (like OWASP Top 10, SQLi, XSS, CSRF, CSP, HSTS, cookie flags, CVSS scoring) "
    "using intuitive everyday analogies and simple language.\n"
    "- For developers and technical questions, provide accurate technical details and copy-pasteable server configuration or code blocks "
    "(e.g. Nginx, Apache, Express, PHP, Python) with clear explanations.\n"
    "- If asked about WebShield AI or its architecture, explain that it performs safe, non-destructive Dynamic Application Security Testing (DAST) "
    "using a Breadth-First Search (BFS) crawler, passive heuristic checks across 10 OWASP categories, and CVSS v3.1 scoring.\n"
    "- Use clean markdown formatting (bold text, bullet points, code blocks) to make your answers easy to read."
)

# High-speed, responsive Gemini models
GEMINI_MODELS = [
    "gemini-3.1-flash-lite",
    "gemini-3.1-flash-lite-preview",
    "gemini-flash-latest"
]


def get_backend_api_key() -> str:
    """Retrieve API key strictly from backend environment files."""
    key = os.getenv("GEMINI_API_KEY", "").strip() or os.getenv("AI_API_KEY", "").strip()
    if not key:
        for env_file in [BASE_DIR / ".env", BASE_DIR / ".env.example"]:
            if env_file.exists():
                try:
                    for line in env_file.read_text(encoding="utf-8").splitlines():
                        if line.startswith("GEMINI_API_KEY"):
                            parts = line.split("=", 1)
                            if len(parts) == 2:
                                val = parts[1].strip().strip('"').strip("'")
                                if val and not val.startswith("your_") and "example" not in val.lower():
                                    return val
                except Exception:
                    pass
    if key and (key.startswith("your_") or "example" in key.lower()):
        return ""
    return key


def call_gemini(prompt: str, api_key: str) -> dict:
    """Send user prompt to Google Gemini API for fast, complete responses."""
    headers = {"Content-Type": "application/json"}
    
    payload = {
        "systemInstruction": {
            "parts": [{"text": SYSTEM_INSTRUCTION}]
        },
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}]
            }
        ],
        "generationConfig": {
            "temperature": 0.7,
            "maxOutputTokens": 3000
        }
    }

    last_error = ""
    for model_name in GEMINI_MODELS:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=16)
            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        text = parts[0].get("text", "").strip()
                        return {
                            "success": True,
                            "model": model_name,
                            "text": text
                        }
            else:
                last_error = f"HTTP {resp.status_code}: {resp.text[:250]}"
        except requests.RequestException as e:
            last_error = str(e)

    return {
        "success": False,
        "error": last_error or "Unable to reach Gemini API servers."
    }


def ask_ai_assistant(question: str, context: str = "", finding_type: str = "", client_api_key: str = "") -> dict:
    """
    Main entry point for WebShield AI Chatbot.
    Ultra-fast and complete answer generation via Google Gemini.
    """
    api_key = get_backend_api_key()

    if not api_key:
        return {
            "title": "WebShield AI Security Advisor",
            "category": "Configuration Notice",
            "content": (
                "Please ensure `GEMINI_API_KEY` is configured in your project `.env` file to enable live AI responses."
            ),
            "is_gemini": False
        }

    prompt_sections = [f"User Question: {question}"]
    if finding_type:
        prompt_sections.append(f"Specific Vulnerability Context: {finding_type}")
    if context:
        prompt_sections.append(f"Website Scan Context: {context}")

    full_prompt = "\n\n".join(prompt_sections)

    result = call_gemini(full_prompt, api_key)

    if result.get("success"):
        return {
            "title": "WebShield AI Security Advisor",
            "category": "Security Advice",
            "content": result.get("text", ""),
            "is_gemini": True,
            "model": result.get("model", "Gemini")
        }
    else:
        return {
            "title": "WebShield AI Security Advisor",
            "category": "Connection Notice",
            "content": (
                f"Could not reach AI services at this moment ({result.get('error')}). Please verify your connection or try again."
            ),
            "is_gemini": False
        }
