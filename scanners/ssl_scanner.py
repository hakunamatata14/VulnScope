
import ipaddress
import re
import socket
import ssl
import certifi

from datetime import datetime, timezone
from urllib.parse import urlparse


# --------------------------------------------------
# TARGET VALIDATION
# --------------------------------------------------

def validate_target(target):
    """Validate and normalize an HTTPS hostname or URL."""

    if not isinstance(target, str) or not target.strip():
        raise ValueError("Please enter a valid domain name.")

    target = target.strip()

    if len(target) > 2048:
        raise ValueError("The target URL is too long.")

    if "://" not in target:
        target = "https://" + target

    try:
        parsed = urlparse(target)

        if parsed.scheme.lower() != "https":
            raise ValueError("Only HTTPS targets are supported.")

        if not parsed.hostname:
            raise ValueError("Invalid domain name.")

        if parsed.username or parsed.password:
            raise ValueError(
                "URLs containing credentials are not allowed."
            )

        if (
            parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "Enter only a domain name, without a path or query."
            )

        hostname = parsed.hostname

        if len(hostname) > 253:
            raise ValueError("Domain name is too long.")

        # Validate IP addresses, including IPv6.
        try:
            ipaddress.ip_address(hostname)

        except ValueError:
            # Normalize internationalized domain names.
            try:
                hostname = hostname.rstrip(".").encode(
                    "idna"
                ).decode("ascii")

            except UnicodeError:
                raise ValueError("Invalid domain name.")

            if not hostname:
                raise ValueError("Invalid domain name.")

            labels = hostname.split(".")

            for label in labels:

                if (
                    not label
                    or len(label) > 63
                    or not re.fullmatch(
                        r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?",
                        label
                    )
                ):
                    raise ValueError("Invalid domain name.")

        # Do not use `or 443`: port 0 must be rejected.
        port = parsed.port

        if port is None:
            port = 443

        if not 1 <= port <= 65535:
            raise ValueError("Invalid port number.")

        return hostname, port

    except ValueError:
        raise

    except Exception:
        raise ValueError("Invalid target URL.")


# --------------------------------------------------
# CERTIFICATE DATE PARSING
# --------------------------------------------------

def parse_certificate_date(date_value):
    """Convert an SSL certificate date into a UTC datetime."""

    if not date_value:
        raise ValueError("Certificate validity date is missing.")

    try:
        return datetime.strptime(
            date_value,
            "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

    except ValueError:
        raise ValueError(
            "Unable to interpret certificate validity date."
        )


# --------------------------------------------------
# SSL/TLS SCANNER
# --------------------------------------------------

def scan_ssl_tls(target, timeout=10):
    """Analyze TLS connection and certificate information."""

    hostname = str(target)

    try:
        hostname, port = validate_target(target)

        # Validate timeout.
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 1 <= timeout <= 60
        ):
            raise ValueError(
                "Timeout must be between 1 and 60 seconds."
            )

        # Create a trusted SSL context.
        context = ssl.create_default_context(
            cafile=certifi.where()
        )

        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        # Establish TCP connection.
        with socket.create_connection(
            (hostname, port),
            timeout=timeout
        ) as connection:

            # Establish verified TLS connection.
            with context.wrap_socket(
                connection,
                server_hostname=hostname
            ) as tls_connection:

                certificate = tls_connection.getpeercert()

                if not certificate:
                    return {
                        "success": False,
                        "target": hostname,
                        "error": (
                            "The server did not provide "
                            "a valid certificate."
                        )
                    }

                # Extract certificate validity dates.
                not_before = parse_certificate_date(
                    certificate.get("notBefore")
                )

                not_after = parse_certificate_date(
                    certificate.get("notAfter")
                )

                current_time = datetime.now(timezone.utc)

                days_remaining = (
                    not_after - current_time
                ).days

                expired = current_time > not_after

                # Extract certificate subject.
                subject = {
                    key: value
                    for group in certificate.get("subject", [])
                    for key, value in group
                }

                # Extract certificate issuer.
                issuer = {
                    key: value
                    for group in certificate.get("issuer", [])
                    for key, value in group
                }

                # Extract TLS cipher information.
                cipher_info = tls_connection.cipher()

                cipher_name = (
                    cipher_info[0]
                    if cipher_info
                    else None
                )

                # Return structured results.
                return {
                    "success": True,
                    "target": hostname,
                    "port": port,
                    "tls_version": tls_connection.version(),
                    "cipher": cipher_name,
                    "certificate": {
                        "subject": subject,
                        "issuer": issuer,
                        "valid_from": not_before.strftime(
                            "%Y-%m-%d %H:%M:%S UTC"
                        ),
                        "valid_until": not_after.strftime(
                            "%Y-%m-%d %H:%M:%S UTC"
                        ),
                        "days_remaining": days_remaining,
                        "expired": expired
                    }
                }

    except ValueError as error:

        return {
            "success": False,
            "target": hostname,
            "error": str(error)
        }

    except socket.timeout:

        return {
            "success": False,
            "target": hostname,
            "error": "Connection timed out."
        }

    except ssl.SSLCertVerificationError:

        return {
            "success": False,
            "target": hostname,
            "error": (
                "Certificate verification failed. "
                "The certificate may be expired, "
                "untrusted, or invalid for this hostname."
            )
        }

    except ssl.SSLError:

        return {
            "success": False,
            "target": hostname,
            "error": "A secure TLS connection could not be established."
        }

    except socket.gaierror:

        return {
            "success": False,
            "target": hostname,
            "error": "The hostname could not be resolved."
        }

    except ConnectionRefusedError:

        return {
            "success": False,
            "target": hostname,
            "error": "The target refused the connection."
        }

    except OSError:

        return {
            "success": False,
            "target": hostname,
            "error": "A network error occurred during the scan."
        }

    except Exception:

        return {
            "success": False,
            "target": hostname,
            "error": "An unexpected SSL/TLS scanner error occurred."
        }


# --------------------------------------------------
# DIRECT TEST
# --------------------------------------------------

if __name__ == "__main__":

    test_target = "example.com"

    print("VulnScope - SSL/TLS Analyzer")
    print("=" * 45)

    result = scan_ssl_tls(test_target)

    print(result)
