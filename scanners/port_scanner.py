
import ipaddress
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET


# --------------------------------------------------
# TARGET VALIDATION
# --------------------------------------------------

def validate_target(target):
    """
    Accept one IP address or a valid hostname.

    Reject CIDR notation, IP ranges, URLs and Nmap arguments.
    """

    if not isinstance(target, str):
        raise ValueError("Target must be a string.")

    target = target.strip()

    if not target or len(target) > 253:
        raise ValueError(
            "Please provide a valid IP address or hostname."
        )

    # Check whether the target is an IP address.
    try:
        ipaddress.ip_address(target)
        return target

    except ValueError:
        pass

    # Validate hostname.
    hostname = target.rstrip(".")

    if not hostname or hostname.startswith("-"):
        raise ValueError("Invalid hostname.")

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
            raise ValueError(
                "Please provide a valid hostname or IP address."
            )

    return hostname


# --------------------------------------------------
# NMAP XML PARSING
# --------------------------------------------------

def parse_nmap_results(xml_output):
    """Extract open TCP ports and service information from Nmap XML."""

    try:
        root = ET.fromstring(xml_output)

    except ET.ParseError as error:
        raise ValueError(
            "Could not parse Nmap XML output."
        ) from error

    if root.tag != "nmaprun":
        raise ValueError("Invalid Nmap XML document.")

    host = root.find("host")

    if host is None:
        raise ValueError(
            "No host information was returned by Nmap."
        )

    ports_element = host.find("ports")
    open_ports = []

    if ports_element is None:
        return open_ports

    for port in ports_element.findall("port"):

        state_element = port.find("state")

        if state_element is None:
            continue

        state = state_element.get("state", "unknown")

        # Only include open ports.
        if state != "open":
            continue

        try:
            port_number = int(port.get("portid"))

        except (TypeError, ValueError):
            continue

        if not 1 <= port_number <= 65535:
            continue

        protocol = port.get("protocol", "tcp")

        service_element = port.find("service")

        service = {
            "name": "unknown",
            "product": "",
            "version": "",
            "extra_info": ""
        }

        if service_element is not None:

            service["name"] = service_element.get(
                "name", "unknown"
            )

            service["product"] = service_element.get(
                "product", ""
            )

            service["version"] = service_element.get(
                "version", ""
            )

            service["extra_info"] = service_element.get(
                "extrainfo", ""
            )

        open_ports.append({
            "port": port_number,
            "protocol": protocol,
            "state": state,
            "service": service["name"],
            "product": service["product"],
            "version": service["version"],
            "extra_info": service["extra_info"]
        })

    return open_ports


# --------------------------------------------------
# PORT SCANNER
# --------------------------------------------------

def scan_ports(target):
    """
    Perform a limited TCP connect scan of the top 100 ports.

    Only scan systems you own or have explicit permission to test.
    """

    validated_target = None

    try:
        # Validate target.
        validated_target = validate_target(target)

        # Locate Nmap.
        nmap_path = shutil.which("nmap")

        if not nmap_path:
            return {
                "success": False,
                "error": (
                    "Nmap was not found. "
                    "Check your Nmap installation and PATH."
                )
            }

        # Build Nmap command.
        command = [
            nmap_path,
            "-sT",
            "-sV",
            "--version-light",
            "--top-ports",
            "100",
            "-oX",
            "-",
            "--",
            validated_target
        ]

        # Execute without a shell.
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
            shell=False
        )

        # Check process result.
        if process.returncode != 0:

            return {
                "success": False,
                "target": validated_target,
                "error": (
                    "Nmap scan failed. "
                    "Check Nmap installation and permissions."
                )
            }

        if not process.stdout.strip():

            return {
                "success": False,
                "target": validated_target,
                "error": "Nmap returned no scan results."
            }

        # Parse XML.
        open_ports = parse_nmap_results(process.stdout)

        # Successful scan response.
        return {
            "success": True,
            "target": validated_target,
            "scan_type": "TCP connect scan - top 100 ports",
            "total_open_ports": len(open_ports),
            "open_ports": open_ports
        }

    except ValueError as error:

        return {
            "success": False,
            "error": str(error)
        }

    except subprocess.TimeoutExpired:

        return {
            "success": False,
            "target": validated_target,
            "error": "Nmap scan timed out after 120 seconds."
        }

    except FileNotFoundError:

        return {
            "success": False,
            "target": validated_target,
            "error": "Nmap executable could not be found."
        }

    except PermissionError:

        return {
            "success": False,
            "target": validated_target,
            "error": "Permission denied while executing Nmap."
        }

    except OSError:

        return {
            "success": False,
            "target": validated_target,
            "error": "A system error occurred while running Nmap."
        }

    except Exception:

        return {
            "success": False,
            "target": validated_target,
            "error": "An unexpected port scanner error occurred."
        }


# --------------------------------------------------
# DIRECT TEST
# --------------------------------------------------

if __name__ == "__main__":

    # Test only against your own computer.
    result = scan_ports("127.0.0.1")

    print("\nVulnScope - Nmap Port Scanner")
    print("=" * 40)
    print(result)
