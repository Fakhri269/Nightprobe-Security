"""
techdetect.py — Technology Stack Detector
"""
import re
import requests
import warnings
warnings.filterwarnings("ignore")

HEADERS = {"User-Agent": "NightProbe-Scanner/1.0"}

# Pattern: (category, name, match_fn)
# match_fn receives: headers dict (lowercase keys), html body string
SIGNATURES = [
    # Web Servers
    ("server",  "Nginx",          lambda h, b: "nginx"       in h.get("server", "").lower()),
    ("server",  "Apache",         lambda h, b: "apache"      in h.get("server", "").lower()),
    ("server",  "LiteSpeed",      lambda h, b: "litespeed"   in h.get("server", "").lower()),
    ("server",  "Microsoft IIS",  lambda h, b: "iis"         in h.get("server", "").lower()),
    ("server",  "Caddy",          lambda h, b: "caddy"       in h.get("server", "").lower()),
    ("server",  "OpenResty",      lambda h, b: "openresty"   in h.get("server", "").lower()),

    # CDN / Proxy
    ("cdn",     "Cloudflare",     lambda h, b: "cloudflare"  in h.get("server", "").lower()
                                            or "cf-ray"      in h),
    ("cdn",     "Fastly",         lambda h, b: "fastly"      in h.get("via", "").lower()
                                            or "x-fastly"    in h),
    ("cdn",     "Akamai",         lambda h, b: "akamai"      in h.get("x-check-cacheable", "").lower()
                                            or "x-akamai"    in str(h)),
    ("cdn",     "AWS CloudFront", lambda h, b: "cloudfront"  in h.get("via", "").lower()
                                            or "x-amz-cf"    in str(h)),

    # Backend / Language
    ("backend", "PHP",            lambda h, b: "php"         in h.get("x-powered-by", "").lower()
                                            or bool(re.search(r'\.php', b))),
    ("backend", "ASP.NET",        lambda h, b: "asp.net"     in h.get("x-powered-by", "").lower()),
    ("backend", "Node.js",        lambda h, b: "node"        in h.get("x-powered-by", "").lower()
                                            or "express"     in h.get("x-powered-by", "").lower()),
    ("backend", "Ruby on Rails",  lambda h, b: bool(re.search(r'_session.*rails|rails', str(h).lower()))),
    ("backend", "Django",         lambda h, b: "csrftoken"   in h.get("set-cookie", "").lower()),
    ("backend", "Laravel",        lambda h, b: "laravel"     in h.get("set-cookie", "").lower()),

    # CMS
    ("cms",     "WordPress",      lambda h, b: "/wp-content/" in b or "/wp-includes/" in b),
    ("cms",     "Joomla",         lambda h, b: "/components/com_" in b),
    ("cms",     "Drupal",         lambda h, b: "drupal" in b.lower() or "drupal" in h.get("x-generator", "").lower()),
    ("cms",     "Ghost",          lambda h, b: "ghost.io" in b or "content/themes/ghost" in b),
    ("cms",     "Shopify",        lambda h, b: "cdn.shopify.com" in b),
    ("cms",     "Wix",            lambda h, b: "static.wix.com" in b or "wixstatic.com" in b),

    # JS Frameworks
    ("frontend","React",          lambda h, b: "react" in b.lower() and ("__react" in b or "reactroot" in b.lower())),
    ("frontend","Vue.js",         lambda h, b: "vue" in b.lower() and ("__vue" in b or "v-app" in b.lower())),
    ("frontend","Angular",        lambda h, b: "ng-version" in b or "angular.min.js" in b),
    ("frontend","Next.js",        lambda h, b: "__NEXT_DATA__" in b or "_next/static" in b),
    ("frontend","Nuxt.js",        lambda h, b: "__NUXT__" in b or "_nuxt/" in b),
    ("frontend","jQuery",         lambda h, b: "jquery" in b.lower()),
    ("frontend","Bootstrap",      lambda h, b: "bootstrap" in b.lower()),

    # Analytics
    ("analytics","Google Analytics", lambda h, b: "google-analytics.com" in b or "gtag(" in b),
    ("analytics","Google Tag Manager",lambda h, b:"googletagmanager.com" in b),
    ("analytics","Hotjar",        lambda h, b: "hotjar.com" in b),
    ("analytics","Facebook Pixel",lambda h, b: "connect.facebook.net" in b),

    # Security
    ("security","reCAPTCHA",      lambda h, b: "recaptcha" in b.lower()),
    ("security","hCaptcha",       lambda h, b: "hcaptcha.com" in b),
    ("security","Cloudflare WAF", lambda h, b: "cf-ray" in h and "__cf_bm" in h.get("set-cookie", "")),
]


def detect_tech(url: str, timeout: int = 8) -> dict:
    """
    Fetch URL and detect technologies by header + body signatures.
    Returns dict: { category: [list of tech names], ... }
    and a flat 'all' list for convenience.
    """
    result = {}

    try:
        r = requests.get(url, timeout=timeout, headers=HEADERS,
                         allow_redirects=True, verify=False)
        h    = {k.lower(): v for k, v in r.headers.items()}
        body = r.text

        for category, name, match_fn in SIGNATURES:
            try:
                if match_fn(h, body):
                    result.setdefault(category, []).append(name)
            except Exception:
                pass

        # Raw server / x-powered-by values not caught above
        raw_server = r.headers.get("Server", "")
        raw_xpb    = r.headers.get("X-Powered-By", "")
        if raw_server and not any(raw_server in v for v in result.get("server", [])):
            result.setdefault("server", []).append(raw_server)
        if raw_xpb and not any(raw_xpb in v for v in result.get("backend", [])):
            result.setdefault("backend", []).append(raw_xpb)

    except requests.exceptions.RequestException as e:
        result["error"] = str(e)

    # Flat list
    result["all"] = [t for cat, items in result.items()
                     if cat not in ("all", "error")
                     for t in items]

    return result