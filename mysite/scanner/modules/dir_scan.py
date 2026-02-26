import requests

paths = [
"/admin",
"/backup",
"/.git",
"/test",
"/old"
]

def scan_dirs(url):

    found = []

    for p in paths:

        target = url + p

        try:

            r = requests.get(target)

            if r.status_code == 200:
                found.append(target)

        except:
            pass

    return found