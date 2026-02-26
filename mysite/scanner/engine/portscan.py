import socket
from urllib.parse import urlparse

COMMON_PORTS = [21,22,25,53,80,110,143,443,3306,8080]

def port_scan(url):
    hostname = urlparse(url).netloc or url

    results = {}

    for port in COMMON_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.7)

        try:
            s.connect((hostname, port))
            results[port] = "open"
        except:
            results[port] = "closed"

        s.close()

    return results
