"""
xss.py — Reflected XSS Scanner
Tests multiple parameters and payloads for reflected XSS.
"""
import requests
import warnings
warnings.filterwarnings("ignore")

PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
    "';alert(1)//",
    "<svg onload=alert(1)>",
]

PARAMS = ["q", "s", "id", "search", "query", "keyword", "term", "input", "name", "page", "url"]

HEADERS = {"User-Agent": "NightProbe-Scanner/1.0"}


def scan_xss(url: str, timeout: int = 6) -> bool:
    """
    Test for reflected XSS by injecting payloads into common GET params.
    Returns True if any payload is reflected in the response body.
    """
    base = url.rstrip("/")

    for payload in PAYLOADS:
        for param in PARAMS:
            try:
                test_url = f"{base}?{param}={requests.utils.quote(payload)}"
                r = requests.get(
                    test_url, timeout=timeout, headers=HEADERS,
                    allow_redirects=True, verify=False
                )
                # Cek apakah payload direfleksikan tanpa encoding
                if payload in r.text:
                    return True
            except requests.exceptions.RequestException:
                continue

    return False
