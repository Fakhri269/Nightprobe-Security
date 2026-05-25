"""
xss.py — Reflected XSS Scanner
Returns list of findings dengan detail: URL, parameter, payload yang direfleksikan.
"""
import requests
import warnings
warnings.filterwarnings("ignore")

PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
    "<svg onload=alert(1)>",
    "';alert(1)//",
    "<body onload=alert(1)>",
    '"><img src=x onerror=alert(1)>',
]

PARAMS = ["q", "s", "id", "search", "query", "keyword", "term",
          "input", "name", "page", "url", "redirect", "ref", "next"]

HEADERS = {"User-Agent": "NightProbe-Scanner/1.0"}


def scan_xss(url: str, timeout: int = 6) -> dict:
    """
    Test reflected XSS via GET params.

    Returns:
        {
          "vulnerable": True/False,
          "findings": [
            {
              "url":     "https://target.com?q=<script>...",
              "param":   "q",
              "payload": "<script>alert(1)</script>",
              "fix":     "Encode/escape semua output dari param 'q'. Gunakan CSP header."
            },
            ...
          ]
        }
    """
    base = url.rstrip("/")
    findings = []
    seen = set()

    for param in PARAMS:
        for payload in PAYLOADS:
            if param in seen:
                break
            try:
                test_url = f"{base}?{param}={requests.utils.quote(payload)}"
                r = requests.get(
                    test_url, timeout=timeout, headers=HEADERS,
                    allow_redirects=True, verify=False
                )
                # Cek apakah payload direfleksikan mentah-mentah (tanpa HTML encoding)
                if payload in r.text:
                    findings.append({
                        "url":     test_url,
                        "param":   param,
                        "payload": payload,
                        "fix": (
                            f"Parameter '{param}' merefleksikan input tanpa encoding. "
                            f"Gunakan htmlspecialchars() / escapeHtml() pada output. "
                            f"Pasang header Content-Security-Policy untuk perlindungan tambahan."
                        ),
                    })
                    seen.add(param)
                    break

            except requests.exceptions.RequestException:
                continue

    return {
        "vulnerable": len(findings) > 0,
        "findings":   findings,
    }
