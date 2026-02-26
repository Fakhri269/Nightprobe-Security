import requests

payload = "' OR '1'='1"

def scan_sqli(url):

    try:
        test = url + "?id=" + payload
        r = requests.get(test)

        errors = [
            "sql syntax",
            "mysql",
            "syntax error",
            "warning"
        ]

        for e in errors:
            if e in r.text.lower():
                return True

    except:
        pass

    return False