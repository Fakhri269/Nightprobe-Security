"""
views.py — NightProbe Security Scanner
Main request handler. Runs all scan modules concurrently using threads.
"""
from django.shortcuts import render
from django.http import JsonResponse
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError

from .engine.crawler import crawl
from .engine.headers import check_headers
from .engine.xss import scan_xss
from .engine.sqli import scan_sqli
from .engine.recon import dns_lookup, whois_lookup
from .engine.network import port_scan
from .engine.sslcheck import ssl_check
from .engine.techdetect import detect_tech
from .engine.api_scan import api_scan


def normalize_url(url: str) -> str | None:
    """
    Pastikan URL valid dan punya scheme http/https.
    Returns normalized URL or None jika tidak valid.
    """
    url = url.strip()
    if not url:
        return None
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        parsed = urlparse(url)
        if not parsed.hostname or "." not in parsed.hostname:
            return None
        return url
    except Exception:
        return None


def home(request):
    return render(request, "scanner.html")


def scan(request):
    raw_url = request.GET.get("url", "")
    url = normalize_url(raw_url)

    if not url:
        return JsonResponse({"error": "URL tidak valid. Contoh: https://example.com"})

    # Jalankan semua modul scan secara concurrent dengan timeout global 60s
    TASKS = {
        "links":   lambda: crawl(url),
        "headers": lambda: check_headers(url),
        "xss":     lambda: scan_xss(url),
        "sqli":    lambda: scan_sqli(url),
        "dns":     lambda: dns_lookup(url),
        "whois":   lambda: whois_lookup(url),
        "ports":   lambda: port_scan(url),
        "ssl":     lambda: ssl_check(url),
        "tech":    lambda: detect_tech(url),
        "api":     lambda: api_scan(url),
    }

    results = {
        "target": url,
        "links":   [],
        "headers": {},
        "xss":     {"vulnerable": False, "findings": []},
        "sqli":    {"vulnerable": False, "findings": []},
        "dns":     {},
        "whois":   {},
        "ports":   {},
        "ssl":     {"valid": False, "error": "Scan tidak selesai"},
        "tech":    {"all": []},
        "api":     [],
    }

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_key = {executor.submit(fn): key for key, fn in TASKS.items()}
        for future in as_completed(future_to_key, timeout=25):
            key = future_to_key[future]
            try:
                results[key] = future.result(timeout=2)
            except Exception as e:
                # Simpan error per modul, jangan crash seluruh scan
                if key in ("xss", "sqli"):
                    results[key] = {"vulnerable": False, "findings": [], "error": str(e)}
                elif key in ("links", "api"):
                    results[key] = []
                elif key in ("ports", "headers"):
                    results[key] = {}
                else:
                    results[key] = {"error": str(e)}

    return JsonResponse(results)
