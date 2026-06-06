import socket
import requests
from urllib.parse import urlparse

TWO_LEVEL_TLDS = {
    'co.id','ac.id','or.id','go.id','sch.id','net.id','web.id','biz.id','my.id',
    'co.uk','org.uk','me.uk','net.uk','ac.uk',
    'com.au','net.au','org.au','co.au',
    'co.jp','ne.jp','or.jp','ac.jp',
    'com.cn','net.cn',
    'com.hk','com.tw','com.sg','com.my','com.ph','com.vn','co.th','co.in',
    'co.nz','co.za','com.br','com.ar','com.pe','co.kr',
}

# Hanya server yang sudah terbukti reliable
RDAP_SERVERS = {
    # Indonesia — paling penting
    'id':     'https://rdap.pandi.id/rdap/domain/',
    'co.id':  'https://rdap.pandi.id/rdap/domain/',
    'ac.id':  'https://rdap.pandi.id/rdap/domain/',
    'or.id':  'https://rdap.pandi.id/rdap/domain/',
    'go.id':  'https://rdap.pandi.id/rdap/domain/',
    'sch.id': 'https://rdap.pandi.id/rdap/domain/',
    'net.id': 'https://rdap.pandi.id/rdap/domain/',
    'web.id': 'https://rdap.pandi.id/rdap/domain/',
    'biz.id': 'https://rdap.pandi.id/rdap/domain/',
    'my.id':  'https://rdap.pandi.id/rdap/domain/',
    # Generic — Verisign sangat reliable
    'com':    'https://rdap.verisign.com/com/v1/domain/',
    'net':    'https://rdap.verisign.com/net/v1/domain/',
    'tv':     'https://rdap.verisign.com/tv/v1/domain/',
    'cc':     'https://rdap.verisign.com/cc/v1/domain/',
    'org':    'https://rdap.publicinterestregistry.org/rdap/domain/',
    # Europe
    'uk':     'https://rdap.nominet.uk/domain/',
    'co.uk':  'https://rdap.nominet.uk/domain/',
    'org.uk': 'https://rdap.nominet.uk/domain/',
    'me.uk':  'https://rdap.nominet.uk/domain/',
    'ac.uk':  'https://rdap.nominet.uk/domain/',
    'de':     'https://rdap.denic.de/domain/',
    'fr':     'https://rdap.nic.fr/domain/',
    'nl':     'https://rdap.sidn.nl/rdap/domain/',
    'eu':     'https://rdap.eu/domain/',
    'it':     'https://rdap.nic.it/domain/',
    'pl':     'https://rdap.dns.pl/rdap/domain/',
    'ru':     'https://rdap.tcinet.ru/domain/',
    'ch':     'https://rdap.nic.ch/domain/',
    'at':     'https://rdap.nic.at/domain/',
    'be':     'https://rdap.dns.be/domain/',
    'se':     'https://rdap.iis.se/domain/',
    'no':     'https://rdap.norid.no/domain/',
    'dk':     'https://rdap.dk-hostmaster.dk/domain/',
    'fi':     'https://rdap.ficora.fi/domain/',
    'cz':     'https://rdap.nic.cz/domain/',
    'ie':     'https://rdap.iedr.ie/domain/',
    'es':     'https://rdap.nic.es/domain/',
    'pt':     'https://rdap.dns.pt/domain/',
    'hu':     'https://rdap.nic.hu/domain/',
    'ro':     'https://rdap.rotld.ro/domain/',
    'rs':     'https://rdap.rnids.rs/domain/',
    'ua':     'https://rdap.ua/domain/',
    'lt':     'https://rdap.domreg.lt/domain/',
    'lv':     'https://rdap.nic.lv/domain/',
    'ee':     'https://rdap.internet.ee/domain/',
    # Asia Pacific
    'jp':     'https://rdap.jprs.jp/domain/',
    'co.jp':  'https://rdap.jprs.jp/domain/',
    'kr':     'https://rdap.kr/domain/',
    'co.kr':  'https://rdap.kr/domain/',
    'cn':     'https://rdap.cnnic.cn/rdap/domain/',
    'com.cn': 'https://rdap.cnnic.cn/rdap/domain/',
    'au':     'https://rdap.auda.org.au/domain/',
    'com.au': 'https://rdap.auda.org.au/domain/',
    'nz':     'https://rdap.srs.net.nz/domain/',
    'co.nz':  'https://rdap.srs.net.nz/domain/',
    'in':     'https://rdap.registry.in/domain/',
    # Americas
    'us':     'https://rdap.nic.us/domain/',
    'ca':     'https://rdap.cira.ca/domain/',
    'br':     'https://rdap.registro.br/domain/',
    'com.br': 'https://rdap.registro.br/domain/',
    'ar':     'https://rdap.nic.ar/domain/',
    'cl':     'https://rdap.nic.cl/domain/',
    'mx':     'https://rdap.mx/domain/',
    # Africa
    'za':     'https://rdap.registry.net.za/domain/',
    'co.za':  'https://rdap.registry.net.za/domain/',
}

# Semua TLD yang tidak ada di RDAP_SERVERS akan pakai fallback ini
RDAP_FALLBACK = 'https://rdap.org/domain/'


def extract_domain(url):
    if not url.startswith("http"):
        url = "http://" + url
    return urlparse(url).hostname


def extract_root_domain(hostname):
    if not hostname:
        return hostname
    parts = hostname.split('.')
    two_level = '.'.join(parts[-2:])
    if two_level in TWO_LEVEL_TLDS:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def get_rdap_url(domain):
    parts     = domain.split('.')
    two_level = '.'.join(parts[-2:])
    tld       = parts[-1]
    if two_level in RDAP_SERVERS:
        return RDAP_SERVERS[two_level] + domain
    if tld in RDAP_SERVERS:
        return RDAP_SERVERS[tld] + domain
    # TLD tidak dikenal → langsung rdap.org (dia yang urus redirect)
    return RDAP_FALLBACK + domain


def dns_lookup(url):
    try:
        domain  = extract_domain(url)
        ip      = socket.gethostbyname(domain)
        all_ips = list(set(socket.gethostbyname_ex(domain)[2]))
        return {"hostname": domain, "ip": ip, "all_ips": all_ips}
    except Exception as e:
        return {"error": str(e)}


def whois_lookup(url):
    try:
        hostname = extract_domain(url)
        domain   = extract_root_domain(hostname)
        rdap_url = get_rdap_url(domain)

        try:
            r = requests.get(
                rdap_url, timeout=10,
                headers={"Accept": "application/rdap+json, application/json"},
                allow_redirects=True
            )
        except Exception:
            # Kalau server spesifik gagal konek, langsung coba fallback
            r = requests.get(
                RDAP_FALLBACK + domain, timeout=10,
                headers={"Accept": "application/rdap+json, application/json"},
                allow_redirects=True
            )

        if r.status_code != 200:
            # Satu kesempatan lagi dengan fallback
            if RDAP_FALLBACK + domain != rdap_url:
                r = requests.get(
                    RDAP_FALLBACK + domain, timeout=10,
                    headers={"Accept": "application/rdap+json, application/json"},
                    allow_redirects=True
                )
            if r.status_code != 200:
                return {"error": f"RDAP tidak tersedia untuk {domain}"}

        d = r.json()

        registrar = None
        org       = None
        for entity in d.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [None, []])[1]
            name  = next((e[3] for e in vcard if e[0] == "fn"), None)
            if "registrar" in roles and not registrar:
                registrar = name
            if "registrant" in roles and not org:
                org = name

        creation_date = expiration_date = updated_date = None
        for event in d.get("events", []):
            action = event.get("eventAction", "")
            date   = event.get("eventDate", "")[:10]
            if action == "registration":
                creation_date = date
            elif action == "expiration":
                expiration_date = date
            elif action == "last changed":
                updated_date = date

        ns = [n.get("ldhName", "").lower()
              for n in d.get("nameservers", [])
              if n.get("ldhName")]

        return {
            "registrar":       registrar,
            "creation_date":   creation_date,
            "expiration_date": expiration_date,
            "updated_date":    updated_date,
            "name_servers":    ns[:4],
            "org":             org,
        }

    except Exception as e:
        return {"error": str(e)}