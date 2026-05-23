"""
crawler.py — Web Crawler
Fetches the target URL and extracts all internal and external links.
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import warnings
warnings.filterwarnings("ignore")

HEADERS = {"User-Agent": "NightProbe-Scanner/1.0"}


def crawl(url: str, timeout: int = 8) -> list:
    """
    Crawl the given URL and return a deduplicated list of all links found.
    Includes both internal and external links.
    """
    links = set()

    try:
        r = requests.get(
            url, timeout=timeout, headers=HEADERS,
            allow_redirects=True, verify=False
        )
        soup = BeautifulSoup(r.text, "html.parser")

        for tag in soup.find_all(["a", "link", "script", "img", "form"], href=True):
            href = tag.get("href") or tag.get("src") or tag.get("action") or ""
            if href and not href.startswith(("#", "javascript:")):
                full = urljoin(url, href)
                if full.startswith(("http://", "https://", "mailto:", "tel:")):
                    links.add(full)

        for tag in soup.find_all(["script", "img", "iframe", "source"], src=True):
            src = tag.get("src", "")
            if src and not src.startswith("data:"):
                full = urljoin(url, src)
                if full.startswith(("http://", "https://")):
                    links.add(full)

    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.RequestException:
        pass
    except Exception:
        pass

    return sorted(links)
