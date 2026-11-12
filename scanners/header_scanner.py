
"""
VulnScope - HTTP Security Header Scanner

Checks common HTTP security headers on authorized public targets.

This is a security-header assessment, not a complete
vulnerability assessment.
"""

import ipaddress
import socket
from urllib.parse import urlparse

import requests


# --------------------------------------------------
# SECURITY HEADER CONFIGURATION
# --------------------------------------------------

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


# --------------------------------------------------
# TARGET VALIDATION
# --------------------------------------------------

def validate_target_url(url):
    """Validate a URL and reject non-public destination addresses."""

    if not isinstance(url, str):
        return None, "Please enter a valid URL."

    url = url.strip()

    if not url:
        return None, "Please enter a target URL."

    if len(url) > 2048:
        return None, "The URL is too long."

    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in ("http", "https"):
            return None, "Only HTTP and HTTPS URLs are allowed."

        if not parsed.hostname:
            return None, "The URL must contain a valid hostname."

        if parsed.username or parsed.password:
            return None, (
                "URLs containing login credentials are not allowed."
            )

        hostname = parsed.hostname

        port = parsed.port

        if port is None:
            port = 443 if parsed.scheme.lower() == "https" else 80

        if not 1 <= port <= 65535:
            return None, "The port number is invalid."

        # Resolve every address and reject the hostname if any
        # returned address is not globally routable.
        addresses = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM
        )

        if not addresses:
            return None, "The hostname could not be resolved."

        resolved_ips = set()

        for address in addresses:

            ip = ipaddress.ip_address(address[4][0])

            if not ip.is_global:
                return None, (
                    "The target resolves to a private or non-public "
                    "IP address. Only public targets are allowed."
                )

            resolved_ips.add(str(ip))

        if not resolved_ips:
            return None, "No public IP address was found."

        return url, None

    except ValueError:
        return None, "The URL or port number is invalid."

    except socket.gaierror:
        return None, "The hostname could not be resolved."

    except OSError:
        return None, "Unable to validate the target hostname."


# --------------------------------------------------
# SEVERITY SUMMARY
# --------------------------------------------------

def calculate_severity_summary(results):
    """Count missing security headers by severity."""

    summary = {
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for item in results:

        if not isinstance(item, dict):
            continue

        if item.get("status") != "Missing":
            continue

        severity = item.get("severity")

        if severity in summary:
            summary[severity] += 1

    return summary


# --------------------------------------------------
# RISK CLASSIFICATION
# --------------------------------------------------

def calculate_risk_level(summary):
    """
    Calculate a preliminary header-based risk level.

    This is not a CVSS score.
    """

    if summary.get("High", 0) > 0:
        return "High"

    if summary.get("Medium", 0) > 0:
        return "Medium"

    if summary.get("Low", 0) > 0:
        return "Low"

    return "Informational"


# --------------------------------------------------
# HTTP SECURITY HEADER SCANNER
# --------------------------------------------------

def scan_security_headers(url):
    """Check HTTP security headers on an authorized public target."""

    validated_url, validation_error = validate_target_url(url)

    if validation_error:
        return {
            "success": False,
            "error": validation_error
        }

    http_session = requests.Session()

    # Do not inherit proxy configuration from environment variables.
    http_session.trust_env = False

    response = None

    try:
        response = http_session.get(
            validated_url,
            timeout=(5, 10),
            allow_redirects=False,
            stream=True,
            verify=True,
            headers={
                "User-Agent": "VulnScope/1.0",
                "Accept": "*/*"
            }
        )

        # Do not automatically follow redirects.
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
        is_https = response.url.lower().startswith("https://")

        results = []

        for header, details in SECURITY_HEADERS.items():

            # HSTS is only applicable to HTTPS connections.
            if header == "Strict-Transport-Security" and not is_https:

                results.append({
                    "header": header,
                    "status": "Not Applicable",
                    "severity": "Informational",
                    "description": (
                        "HSTS is only applicable when the target "
                        "is accessed over HTTPS."
                    ),
                    "value": None
                })

                continue

            if header in response_headers:

                results.append({
                    "header": header,
                    "status": "Present",
                    "severity": "Informational",
                    "description": details["description"],
                    "value": response_headers.get(header)
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
            1
            for item in results
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
            "error": "The target did not respond within the allowed time."
        }

    except requests.exceptions.SSLError:
        return {
            "success": False,
            "error": "SSL certificate verification failed."
        }

    except requests.exceptions.RequestException:
        return {
            "success": False,
            "error": (
                "Unable to connect to the target. "
                "Check the URL and network connection."
            )
        }

    except OSError:
        return {
            "success": False,
            "error": "A network error occurred during the scan."
        }

    finally:

        if response is not None:
            response.close()

        http_session.close()
