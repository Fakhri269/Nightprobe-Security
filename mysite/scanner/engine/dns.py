import socket
from urllib.parse import urlparse

def dns_lookup(url):
    try:
        hostname = urlparse(url).netloc or url

        ip = socket.gethostbyname(hostname)

        all_ips = socket.gethostbyname_ex(hostname)[2]

        return {
            "hostname": hostname,
            "ip": ip,
            "all_ips": all_ips
        }

    except Exception as e:
        return {"error": str(e)}