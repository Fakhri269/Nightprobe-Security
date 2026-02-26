import socket
from urllib.parse import urlparse


COMMON_PORTS = [21,22,25,53,80,110,143,443,3306,8080]


def extract_domain(url):
    if not url.startswith("http"):
        url = "http://" + url
    return urlparse(url).hostname


def port_scan(url):

    host = extract_domain(url)
    result = {}

    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        try:
            sock.connect((host, port))
            result[str(port)] = "open"
        except:
            result[str(port)] = "closed"

        sock.close()

    return result