"""
sslcheck.py — SSL/TLS Certificate Checker
"""
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse


def ssl_check(url: str, timeout: int = 8) -> dict:
    """
    Connect to host:443 and return SSL certificate details.
    """
    result = {
        "valid":          False,
        "issuer":         None,
        "subject":        None,
        "issued_on":      None,
        "expires":        None,
        "days_remaining": None,
        "tls_version":    None,
        "cipher":         None,
        "san":            [],
        "error":          None,
    }

    try:
        hostname = urlparse(url).hostname
        if not hostname:
            result["error"] = "Invalid URL"
            return result

        ctx = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert   = ssock.getpeercert()
                cipher = ssock.cipher()

                # Subject / Issuer
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer",  []))

                result["subject"] = subject.get("commonName", "-")
                result["issuer"]  = issuer.get("organizationName",
                                    issuer.get("commonName", "-"))

                # Dates
                DATE_FMT = "%b %d %H:%M:%S %Y %Z"
                not_before = cert.get("notBefore")
                not_after  = cert.get("notAfter")

                if not_before:
                    dt = datetime.strptime(not_before, DATE_FMT).replace(tzinfo=timezone.utc)
                    result["issued_on"] = dt.strftime("%Y-%m-%d")

                if not_after:
                    dt = datetime.strptime(not_after, DATE_FMT).replace(tzinfo=timezone.utc)
                    result["expires"]        = dt.strftime("%Y-%m-%d")
                    result["days_remaining"] = (dt - datetime.now(timezone.utc)).days

                # SAN
                result["san"] = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

                # Cipher & TLS version
                if cipher:
                    result["cipher"]      = f"{cipher[0]} ({cipher[2]}bit)"
                    result["tls_version"] = cipher[1]

                result["valid"] = True

    except ssl.CertificateError as e:
        result["error"] = f"Certificate error: {e}"
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except OSError as e:
        result["error"] = str(e)

    return result