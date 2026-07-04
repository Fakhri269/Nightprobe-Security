"""
views.py — NightProbe Security Scanner
Main request handler. Runs all scan modules concurrently using threads.
"""
import os
import json
import requests as http_requests
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
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
        for future in as_completed(future_to_key, timeout=65):
            key = future_to_key[future]
            try:
                results[key] = future.result(timeout=5)
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


@csrf_exempt
def ai_chat(request):
    """
    AI Chat endpoint. Accepts POST with {firebase_token, message, context}.
    Verifies Firebase ID token, then calls Gemini API using server-side key.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    try:
        body = json.loads(request.body)
        firebase_token = body.get('firebase_token', '')
        message = body.get('message', '').strip()
        context = body.get('context', '')
    except Exception:
        return JsonResponse({'error': 'Invalid JSON body'}, status=400)

    if not message:
        return JsonResponse({'error': 'Message is required'}, status=400)

    # Verify Firebase ID Token using Firebase REST API
    if not firebase_token:
        return JsonResponse({'error': 'Authentication required. Please sign in.'}, status=401)

    try:
        api_key = "AIzaSyDnV1OVyK2hGm4BPqzrI3RNNb2Lz58nxto" # Public Firebase API key
        verify_url = f'https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={api_key}'
        verify_resp = http_requests.post(verify_url, json={"idToken": firebase_token}, timeout=10)
        token_data = verify_resp.json()
        if 'error' in token_data:
            return JsonResponse({'error': 'Invalid or expired session. Please sign in again.'}, status=401)
    except Exception as e:
        return JsonResponse({'error': f'Could not verify session: {str(e)}'}, status=401)

    # Get Gemini API key from environment
    gemini_key = os.environ.get('GEMINI_API_KEY', '')
    if not gemini_key:
        return JsonResponse({'error': 'AI service not configured on server. Contact admin.'}, status=503)

    # Build system prompt
    system_prompt = """Kamu adalah NightProbe AI, asisten cybersecurity ahli yang berbicara bahasa Indonesia.
Kamu bisa membantu: analisis keamanan web, menjelaskan celah (XSS, SQLi, dll), menulis kode patch/fix, menjawab pertanyaan IT, koding, dan hacking edukasional.
Jawab dengan format Markdown yang rapi dan ringkas."""

    if context:
        system_prompt += f"\n\nKonteks scan website saat ini:\n{context}"

    full_prompt = f"{system_prompt}\n\nUser: {message}"

    # Call Gemini API
    try:
        gemini_url = f'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}'
        payload = {'contents': [{'parts': [{'text': full_prompt}]}]}
        resp = http_requests.post(gemini_url, json=payload, timeout=30)
        data = resp.json()
        if 'error' in data:
            return JsonResponse({'error': f"Gemini error: {data['error'].get('message', 'Unknown')}"}, status=502)
        reply = data['candidates'][0]['content']['parts'][0]['text']
        return JsonResponse({'reply': reply})
    except Exception as e:
        return JsonResponse({'error': f'AI call failed: {str(e)}'}, status=502)
