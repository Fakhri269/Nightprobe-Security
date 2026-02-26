"""
api_scan.py — Common API Endpoint Scanner
"""
import requests
import warnings
warnings.filterwarnings("ignore")

COMMON_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/rest", "/swagger", "/swagger.json",
    "/swagger-ui.html", "/openapi", "/openapi.json",
    "/v1", "/v2", "/admin/api", "/api/docs",
    "/wp-json", "/wp-json/wp/v2", "/.well-known/openapi.json",
]

HEADERS = {"User-Agent": "NightProbe-Scanner/1.0"}


def api_scan(url: str, timeout: int = 5) -> list:
    """
    Probe common API endpoints on the target URL.
    Returns list of dicts: {url, status_code, content_type}
    """
    found = []
    base  = url.rstrip("/")

    for path in COMMON_PATHS:
        target = base + path
        try:
            r = requests.get(
                target, timeout=timeout, headers=HEADERS,
                allow_redirects=True, verify=False
            )
            if r.status_code < 400:
                ct = r.headers.get("Content-Type", "")
                found.append({
                    "url":          target,
                    "status_code":  r.status_code,
                    "content_type": ct.split(";")[0].strip(),
                })
        except requests.exceptions.RequestException:
            pass

    return found