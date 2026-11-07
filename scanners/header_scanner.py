
import ipaddress
import socket
from urllib.parse import urlparse

import requests


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "description": (
            "Helps protect against Cross-Site Scripting (XSS) "
            "and content injection."
        )
    },
    "Strict-Transport-Security": {
        "severity": "High",
        "description": (
            "Instructs browsers to use HTTPS for future connections."
        )
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "description": "Helps prevent MIME-type sniffing."
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "Helps protect against clickjacking."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": (
            "Controls how much referrer information browsers send."
        )
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": (
            "Controls access to browser features and APIs."
        )
    }
}


def validate_target_url(url):
    """Validate a target URL before making an HTTP request."""

    if not isinstance(url, str):
        return None, "Please enter a valid URL."

    url = url.strip()

    if not url:
        return None, "Please enter a target URL."

    if len(url) > 2048:
        return None, "The URL is too long."

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return None, "Only HTTP and HTTPS URLs are allowed."

        if not parsed.hostname:
            return None, "The URL must contain a valid hostname."

        if parsed.username or parsed.password:
            return None, "URLs containing login credentials are not allowed."

        hostname = parsed.hostname
        port = parsed.port

        if port is None:
            port = 443 if parsed.scheme == "https" else 80

        addresses = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM
        )

        if not addresses:
            return None, "The hostname could not be resolved."

        for address in addresses:
            ip_address = ipaddress.ip_address(address[4][0])

            if not ip_address.is_global:
                return None, (
                    "The target resolves to a private or non-public "
                    "IP address. Only public targets are allowed."
                )

        return url, None

    except ValueError:
        return None, "The URL or port number is invalid."

    except socket.gaierror:
        return None, "The hostname could not be resolved."

    except OSError:
        return None, "Unable to validate the target hostname."


def calculate_severity_summary(results):
    """
    Count missing security headers by severity.

    Present headers are not counted as vulnerabilities.
    """

    summary = {
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for item in results:
        if item["status"] == "Missing":
            severity = item["severity"]

            if severity in summary:
                summary[severity] += 1

    return summary


def calculate_risk_level(summary):
    """
    Calculate a preliminary risk level based on missing headers.

    This is a simple header-based indicator, not a CVSS score.
    """

    if summary["High"] > 0:
        return "High"

    if summary["Medium"] > 0:
        return "Medium"

    if summary["Low"] > 0:
        return "Low"

    return "Informational"


def scan_security_headers(url):
    """Check HTTP security headers for an authorized public target."""

    validated_url, validation_error = validate_target_url(url)

    if validation_error:
        return {
            "success": False,
            "error": validation_error
        }

    session = requests.Session()
    session.trust_env = False

    try:
        response = session.get(
            validated_url,
            timeout=10,
            allow_redirects=False,
            headers={
                "User-Agent": "VulnScope/1.0"
            }
        )

        if 300 <= response.status_code < 400:
            return {
                "success": False,
                "error": (
                    "The target returned an HTTP redirect. "
                    "Redirects are not followed automatically. "
                    "Enter the final destination URL if authorized."
                )
            }

        response_headers = response.headers
        results = []

        for header, details in SECURITY_HEADERS.items():

            if header in response_headers:
                results.append({
                    "header": header,
                    "status": "Present",
                    "severity": "Informational",
                    "description": details["description"],
                    "value": response_headers[header]
                })

            else:
                results.append({
                    "header": header,
                    "status": "Missing",
                    "severity": details["severity"],
                    "description": details["description"],
                    "value": None
                })

        missing_count = sum(
            1 for item in results
            if item["status"] == "Missing"
        )

        severity_summary = calculate_severity_summary(results)

        risk_level = calculate_risk_level(severity_summary)

        return {
            "success": True,
            "target": validated_url,
            "final_url": response.url,
            "status_code": response.status_code,
            "results": results,
            "total_headers_checked": len(SECURITY_HEADERS),
            "missing_headers": missing_count,
            "severity_summary": severity_summary,
            "risk_level": risk_level
        }

    except requests.exceptions.Timeout:
        return {
            "success": False,
            "error": "The request timed out."
        }

    except requests.exceptions.SSLError:
        return {
            "success": False,
            "error": "SSL certificate verification failed."
        }

    except requests.exceptions.RequestException as error:
        return {
            "success": False,
            "error": str(error)
        }

    finally:
        session.close()
