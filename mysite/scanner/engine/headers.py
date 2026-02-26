import requests

def check_headers(url):

    result = []

    try:
        r = requests.get(url)
        h = r.headers

        if "Content-Security-Policy" not in h:
            result.append("Missing CSP")

        if "X-Frame-Options" not in h:
            result.append("Missing X-Frame-Options")

        if "X-Content-Type-Options" not in h:
            result.append("Missing X-Content-Type-Options")

    except:
        result.append("Connection error")

    return result