import requests

HEADERS = [
"Content-Security-Policy",
"X-Frame-Options",
"Strict-Transport-Security",
"X-XSS-Protection",
"X-Content-Type-Options"
]

def scan_headers(url):

    result = {}

    r = requests.get(url)

    for h in HEADERS:

        if h in r.headers:
            result[h] = "present"
        else:
            result[h] = "missing"

    return result