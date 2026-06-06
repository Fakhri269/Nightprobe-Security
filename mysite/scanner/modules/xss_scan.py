import requests

payloads = [
"<script>alert(1)</script>",
"<img src=x onerror=alert(1)>"
]

def scan_xss(url):

    found = []

    for p in payloads:

        test = url + "?q=" + p

        try:

            r = requests.get(test)

            if p in r.text:
                found.append(test)

        except:
            pass

    return found