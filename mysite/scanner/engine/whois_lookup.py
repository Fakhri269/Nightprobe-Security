import requests
from urllib.parse import urlparse

TWO_LEVEL_TLDS = {
    'co.id','ac.id','or.id','go.id','sch.id','net.id','web.id',
    'co.uk','ac.uk','org.uk','me.uk','net.uk',
    'com.au','net.au','org.au','co.au',
    'co.nz','co.za','co.jp','or.jp','co.kr',
}

def extract_root_domain(hostname):
    if not hostname:
        return hostname
    parts = hostname.split('.')
    two_level = '.'.join(parts[-2:])
    if two_level in TWO_LEVEL_TLDS:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])

def whois_lookup(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        hostname = urlparse(url).hostname or url
        domain   = extract_root_domain(hostname)

        # Step 1: hit rdap.org, ambil redirect location
        rdap_url = f"https://rdap.org/domain/{domain}"
        r1 = requests.get(rdap_url, timeout=10,
                          headers={"Accept": "application/json"},
                          allow_redirects=True)  # follow redirect otomatis

        if r1.status_code != 200:
            return {"error": f"RDAP status {r1.status_code} untuk {domain}"}

        d = r1.json()

        # Parse registrar & org
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

        # Parse dates
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

        # Parse nameservers
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
            "domain":          domain,
        }

    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import sys, json
    url = sys.argv[1] if len(sys.argv) > 1 else "https://google.com"
    print(json.dumps(whois_lookup(url), indent=2))