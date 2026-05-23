"""
network.py — Port Scanner
Scans common ports concurrently using threads.
"""
import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor


COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 5432, 6379, 8080]


def extract_domain(url: str) -> str:
    if not url.startswith("http"):
        url = "http://" + url
    return urlparse(url).hostname or ""


def _check_port(host: str, port: int, timeout: float = 1.5) -> tuple[int, str]:
    """Returns (port, 'open'|'closed')."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, "open"
    except Exception:
        return port, "closed"


def port_scan(url: str) -> dict:
    """
    Scan common ports concurrently.
    Returns dict: { "port": "open" | "closed" }
    """
    host = extract_domain(url)
    if not host:
        return {"error": "Hostname tidak valid"}

    result = {}

    # Semua port di-scan secara parallel → selesai dalam ~1.5 detik, bukan 12 detik
    with ThreadPoolExecutor(max_workers=len(COMMON_PORTS)) as executor:
        futures = [executor.submit(_check_port, host, port) for port in COMMON_PORTS]
        for future in futures:
            try:
                port, status = future.result(timeout=3)
                result[str(port)] = status
            except Exception:
                pass

    return result
