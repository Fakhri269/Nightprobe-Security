import requests
from bs4 import BeautifulSoup

def get_headers(url):

    try:
        r = requests.get(url, timeout=5)

        headers = {}

        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security"
        ]

        for h in security_headers:
            headers[h] = r.headers.get(h, "Missing")

        return headers

    except:
        return {"error": "request failed"}


def extract_links(url):

    try:
        r = requests.get(url)
        soup = BeautifulSoup(r.text, "html.parser")

        links = []

        for a in soup.find_all("a", href=True):
            links.append(a["href"])

        return links[:50]

    except:
        return []