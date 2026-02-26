import requests

payload = "<script>alert(1)</script>"

def scan_xss(url):

    try:
        test = url + "?q=" + payload
        r = requests.get(test)

        if payload in r.text:
            return True

    except:
        pass

    return False