from django.shortcuts import render
from django.http import JsonResponse

from .engine.crawler import crawl
from .engine.headers import check_headers
from .engine.xss import scan_xss
from .engine.sqli import scan_sqli
from .engine.recon import dns_lookup, whois_lookup
from .engine.network import port_scan
from .engine.sslcheck import ssl_check
from .engine.techdetect import detect_tech
from .engine.api_scan import api_scan


def home(request):
    return render(request, "scanner.html")


def scan(request):
    url = request.GET.get("url")

    if not url:
        return JsonResponse({"error": "url missing"})

    result = {
        "target":  url,
        "links":   crawl(url),
        "headers": check_headers(url),
        "xss":     scan_xss(url),
        "sqli":    scan_sqli(url),
        "dns":     dns_lookup(url),
        "whois":   whois_lookup(url),
        "ports":   port_scan(url),
        "ssl":     ssl_check(url),
        "tech":    detect_tech(url),
        "api":     api_scan(url),
    }

    return JsonResponse(result)
