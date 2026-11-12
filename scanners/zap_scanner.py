
import ipaddress
import os
import re
import socket
import time

from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import requests
from dotenv import load_dotenv


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[1]

load_dotenv(BASE_DIR / ".env")

ZAP_BASE_URL = os.getenv(
    "ZAP_BASE_URL",
    "http://127.0.0.1:8080"
).rstrip("/")

ZAP_API_KEY = os.getenv("ZAP_API_KEY", "").strip()

REQUEST_TIMEOUT = 15
MAX_ALERTS = 10000


# --------------------------------------------------
# TARGET VALIDATION
# --------------------------------------------------

def validate_target(target):
    """
    Validate an HTTP or HTTPS target URL.

    Reject private, loopback, link-local and other
    non-public destinations.
    """

    if not isinstance(target, str) or not target.strip():
        raise ValueError("Please provide a target URL.")

    target = target.strip()

    if len(target) > 2048:
        raise ValueError("Target URL is too long.")

    if any(char.isspace() for char in target):
        raise ValueError("Target URL cannot contain whitespace.")

    if "://" not in target:
        target = "https://" + target

    try:
        parsed = urlsplit(target)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError(
                "Only HTTP and HTTPS targets are supported."
            )

        hostname = parsed.hostname

        if not hostname:
            raise ValueError("Invalid target hostname.")

        if parsed.username or parsed.password:
            raise ValueError(
                "URLs containing credentials are not allowed."
            )

        if parsed.fragment:
            raise ValueError(
                "URL fragments are not supported."
            )

        port = parsed.port

        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Invalid target port.")

        hostname = hostname.rstrip(".")

        if not hostname:
            raise ValueError("Invalid target hostname.")

        # Normalize internationalized hostnames.
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError("Invalid target hostname.")

        # Validate IP addresses or resolve hostnames.
        try:
            address = ipaddress.ip_address(hostname)
            resolved_addresses = [address]

        except ValueError:

            if len(hostname) > 253:
                raise ValueError("Target hostname is too long.")

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
                    raise ValueError("Invalid target hostname.")

            try:
                address_info = socket.getaddrinfo(
                    hostname,
                    port or (443 if parsed.scheme == "https" else 80),
                    type=socket.SOCK_STREAM
                )

            except socket.gaierror:
                raise ValueError(
                    "The target hostname could not be resolved."
                )

            resolved_addresses = []

            for item in address_info:
                resolved_addresses.append(
                    ipaddress.ip_address(item[4][0])
                )

        if not resolved_addresses:
            raise ValueError(
                "The target has no resolvable IP addresses."
            )

        # Reject the hostname if any resolved address is non-public.
        for address in resolved_addresses:

            if not address.is_global:
                raise ValueError(
                    "Private or non-public target addresses "
                    "are not allowed."
                )

        # Preserve the original authority, including IPv6 brackets
        # and an explicitly supplied port.
        return urlunsplit((
            parsed.scheme.lower(),
            parsed.netloc,
            parsed.path or "/",
            parsed.query,
            ""
        ))

    except ValueError:
        raise

    except Exception:
        raise ValueError("Invalid target URL.")


# --------------------------------------------------
# ZAP API CONFIGURATION VALIDATION
# --------------------------------------------------

def validate_zap_api_url():
    """Ensure the ZAP API endpoint is a local HTTP service."""

    try:
        parsed = urlsplit(ZAP_BASE_URL)

        if parsed.scheme.lower() != "http":
            raise ValueError("ZAP API must use local HTTP.")

        if not parsed.hostname:
            raise ValueError("Invalid ZAP API hostname.")

        if parsed.username or parsed.password:
            raise ValueError("ZAP API credentials are not allowed in its URL.")

        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise ValueError("Invalid ZAP API base URL.")

        port = parsed.port

        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Invalid ZAP API port.")

        hostname = parsed.hostname

        if hostname.lower() == "localhost":
            return

        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            raise ValueError(
                "ZAP API must use localhost or a loopback IP address."
            )

        if not address.is_loopback:
            raise ValueError(
                "ZAP API must use localhost or a loopback IP address."
            )

    except ValueError:
        raise

    except Exception:
        raise ValueError("Invalid ZAP API configuration.")


# --------------------------------------------------
# ZAP CLIENT
# --------------------------------------------------

class ZAPClient:
    """Communicate with the local OWASP ZAP API."""

    def __init__(self):

        if not ZAP_API_KEY:
            raise ValueError(
                "ZAP_API_KEY is missing from the .env file."
            )

        validate_zap_api_url()

        self.session = requests.Session()

        # Do not inherit proxy settings from environment variables.
        self.session.trust_env = False

        self.deadline = None

    def close(self):
        """Close the HTTP session."""

        self.session.close()

    def set_deadline(self, deadline):
        """Set the overall scan deadline."""

        self.deadline = deadline

    def api_get(self, endpoint, params=None):
        """Send an authenticated GET request to the ZAP API."""

        request_params = dict(params or {})
        request_params["apikey"] = ZAP_API_KEY

        request_timeout = REQUEST_TIMEOUT

        if self.deadline is not None:

            remaining = self.deadline - time.monotonic()

            if remaining <= 0:
                raise TimeoutError(
                    "The overall ZAP scan timeout was reached."
                )

            request_timeout = min(
                REQUEST_TIMEOUT,
                remaining
            )

        try:
            response = self.session.get(
                f"{ZAP_BASE_URL}/JSON/{endpoint}/",
                params=request_params,
                timeout=request_timeout
            )

            response.raise_for_status()

            data = response.json()

        except requests.exceptions.Timeout:
            raise TimeoutError(
                "The ZAP API request timed out."
            )

        except requests.exceptions.JSONDecodeError:
            raise RuntimeError(
                "ZAP returned an invalid JSON response."
            )

        except requests.exceptions.RequestException:
            raise RuntimeError(
                "Unable to communicate with the ZAP API."
            )

        if not isinstance(data, dict):
            raise RuntimeError(
                "Unexpected response from the ZAP API."
            )

        if "code" in data and "message" in data:
            raise RuntimeError(
                "The ZAP API reported an operation error."
            )

        return data

    def get_version(self):

        data = self.api_get("core/view/version")

        return data.get("version", "Unknown")

    def start_spider(self, target, max_children=20):

        data = self.api_get(
            "spider/action/scan",
            {
                "url": target,
                "maxChildren": max_children,
                "recurse": "true"
            }
        )

        scan_id = data.get("scan")

        if scan_id is None:
            raise RuntimeError(
                "ZAP did not return a spider scan ID."
            )

        return str(scan_id)

    def get_spider_status(self, scan_id):

        data = self.api_get(
            "spider/view/status",
            {"scanId": scan_id}
        )

        try:
            status = int(data.get("status", 0))
        except (TypeError, ValueError):
            raise RuntimeError(
                "ZAP returned an invalid spider status."
            )

        if not 0 <= status <= 100:
            raise RuntimeError(
                "ZAP returned an unexpected spider status."
            )

        return status

    def get_passive_scan_queue(self):

        data = self.api_get(
            "pscan/view/recordsToScan"
        )

        try:
            return int(data.get("recordsToScan", 0))
        except (TypeError, ValueError):
            raise RuntimeError(
                "ZAP returned an invalid passive scan queue size."
            )

    def get_alerts(self, target, page_size=500):
        """Retrieve matching alerts in bounded pages."""

        alerts = []
        start = 0

        while True:

            data = self.api_get(
                "core/view/alerts",
                {
                    "baseurl": target,
                    "start": start,
                    "count": page_size
                }
            )

            page = data.get("alerts", [])

            if not isinstance(page, list):
                raise RuntimeError(
                    "Unexpected ZAP alerts response."
                )

            alerts.extend(page)

            if len(alerts) > MAX_ALERTS:
                raise RuntimeError(
                    "The alert limit was reached. "
                    "Narrow the scan scope and try again."
                )

            if len(page) < page_size:
                break

            start += len(page)

        return alerts


# --------------------------------------------------
# ZAP SCANNER
# --------------------------------------------------

def scan_with_zap(target, max_children=20, timeout=180):
    """
    Run a bounded ZAP spider and passive scan.

    No active attack scan is performed.

    Only scan systems you own or have explicit permission to test.
    """

    stage = "initialization"
    client = None
    validated_target = ""

    try:
        validated_target = validate_target(target)

        if (
            isinstance(max_children, bool)
            or not isinstance(max_children, int)
            or not 1 <= max_children <= 50
        ):
            raise ValueError(
                "max_children must be between 1 and 50."
            )

        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, int)
            or not 30 <= timeout <= 600
        ):
            raise ValueError(
                "timeout must be between 30 and 600 seconds."
            )

        client = ZAPClient()

        start_time = time.monotonic()
        deadline = start_time + timeout

        client.set_deadline(deadline)

        # Check ZAP connection.
        stage = "ZAP connection"

        version = client.get_version()

        # Stage 1: Spider scan.
        stage = "spider scan"

        scan_id = client.start_spider(
            validated_target,
            max_children=max_children
        )

        spider_status = 0

        while True:

            spider_status = client.get_spider_status(scan_id)

            if spider_status >= 100:
                break

            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "ZAP spider scan timed out."
                )

            time.sleep(min(2, max(0, deadline - time.monotonic())))

        # Stage 2: Passive scan.
        stage = "passive scan"

        # Three consecutive empty readings are required.
        empty_readings = 0

        while empty_readings < 3:

            remaining = client.get_passive_scan_queue()

            if remaining == 0:
                empty_readings += 1
            else:
                empty_readings = 0

            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "ZAP passive scan timed out."
                )

            if empty_readings < 3:
                time.sleep(
                    min(2, max(0, deadline - time.monotonic()))
                )

        # Stage 3: Retrieve alerts.
        stage = "alert retrieval"

        alerts = client.get_alerts(validated_target)

        findings = []

        for alert in alerts:

            if not isinstance(alert, dict):
                continue

            findings.append({
                "name": alert.get("name", "Unknown"),
                "risk": alert.get("risk", "Informational"),
                "confidence": alert.get("confidence", ""),
                "url": alert.get("url", ""),
                "method": alert.get("method", ""),
                "parameter": alert.get("param", ""),
                "description": alert.get("description", ""),
                "solution": alert.get("solution", ""),
                "reference": alert.get("reference", ""),
                "cwe_id": alert.get("cweid", ""),
                "wasc_id": alert.get("wascid", ""),
                "plugin_id": alert.get("pluginId", "")
            })

        # Stage 4: Severity summary.
        summary = {
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0
        }

        for finding in findings:

            risk = str(
                finding.get("risk", "Informational")
            ).strip().lower()

            if risk in summary:
                summary[risk] += 1

        return {
            "success": True,
            "target": validated_target,
            "zap_version": version,
            "scan_type": "Spider + Passive Scan",
            "spider_status": spider_status,
            "total_findings": len(findings),
            "summary": summary,
            "findings": findings
        }

    except (ValueError, RuntimeError, TimeoutError) as error:

        return {
            "success": False,
            "target": validated_target,
            "error": f"{stage}: {error}"
        }

    except Exception:

        return {
            "success": False,
            "target": validated_target,
            "error": (
                f"{stage}: An unexpected ZAP scanner error occurred."
            )
        }

    finally:

        if client is not None:
            client.close()


# --------------------------------------------------
# DIRECT TEST
# --------------------------------------------------

if __name__ == "__main__":

    print("VulnScope - OWASP ZAP Scanner")
    print("=" * 40)

    print("ZAP API configured:", bool(ZAP_API_KEY))
    print("ZAP address:", ZAP_BASE_URL)

    try:
        client = ZAPClient()

        try:
            print("ZAP version:", client.get_version())
            print("ZAP API connection: OK")

        finally:
            client.close()

    except Exception:
        print(
            "ZAP API connection failed. "
            "Check ZAP configuration and API availability."
        )
