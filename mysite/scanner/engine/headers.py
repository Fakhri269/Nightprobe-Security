"""
headers.py — Security HTTP Headers Checker
Returns dict: { "Header-Name": "present" | "missing" }
"""
import requests
import warnings
warnings.filterwarnings("ignore")

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
]

HEADERS = {"User-Agent": "NightProbe-Scanner/1.0"}


def check_headers(url: str, timeout: int = 8) -> dict:
    """
    Fetch the URL and check for presence of security headers.
    Returns dict: { "Header-Name": "present" | "missing" }
    On connection error, returns { "error": "..." }
    """
    result = {}

    try:
        r = requests.get(
            url, timeout=timeout, headers=HEADERS,
            allow_redirects=True, verify=False
        )
        h_lower = {k.lower(): v for k, v in r.headers.items()}

        for header in SECURITY_HEADERS:
            result[header] = "present" if header.lower() in h_lower else "missing"

    except requests.exceptions.Timeout:
        result["error"] = "Connection timed out"
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"Connection error: {e}"
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)

    return result
