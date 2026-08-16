"""
Log Parser with Regex IP Extraction and Threat Intelligence Enrichment
Capstone Part 4 — Task 2

Usage:
    python log_enricher.py <log_file_path>

Example:
    python log_enricher.py sample_logs/firewall.log
"""

import sys
import re
import json
import ipaddress
import requests


# Regex pattern to match IPv4 addresses in dotted-decimal notation.
# Matches four groups of 1-3 digits separated by dots.
# Uses word boundaries (\b) to avoid matching partial numbers.
IPV4_PATTERN = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

# Private/reserved IP ranges to skip — these are internal addresses
# that should not be sent to external threat intelligence APIs
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("0.0.0.0/8"),        # Invalid
]


def is_private_ip(ip_str: str) -> bool:
    """
    Check if an IP address falls within a private or reserved range.

    Args:
        ip_str: The IP address string to check.

    Returns:
        True if the IP is private/reserved, False if it's a public IP.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in network for network in PRIVATE_RANGES)
    except ValueError:
        # Invalid IP address format (e.g., 999.999.999.999)
        return True


def extract_public_ips(log_file_path: str) -> set:
    """
    Read a log file and extract all unique public IPv4 addresses.

    Args:
        log_file_path: Path to the log file to parse.

    Returns:
        A set of unique public IP address strings.
    """
    public_ips = set()  # Using a set for automatic deduplication

    try:
        with open(log_file_path, "r") as f:
            for line in f:
                # Find all IPv4 addresses in the current log line
                matches = IPV4_PATTERN.findall(line)
                for ip in matches:
                    # Validate IP format and skip private ranges
                    try:
                        ipaddress.ip_address(ip)  # Validate format
                        if not is_private_ip(ip):
                            public_ips.add(ip)
                    except ValueError:
                        continue  # Skip invalid IPs (e.g., 999.999.999.999)
    except FileNotFoundError:
        print(f"Error: Log file '{log_file_path}' not found.")
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied reading '{log_file_path}'.")
        sys.exit(1)

    return public_ips


def enrich_ip(ip: str) -> dict:
    """
    Query ip-api.com REST API for threat intelligence on a public IP.

    Args:
        ip: The public IP address to look up.

    Returns:
        Dictionary with enrichment results (country, ISP, proxy/VPN status).
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,isp,hosting,proxy,mobile"

    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()  # Raise exception for HTTP errors (4xx, 5xx)

        data = response.json()

        if data.get("status") == "fail":
            return {
                "ip": ip,
                "error": data.get("message", "Unknown error from API")
            }

        return {
            "ip": ip,
            "country": data.get("country", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "is_hosting": data.get("hosting", False),
            "is_proxy": data.get("proxy", False),
            "is_mobile": data.get("mobile", False),
            "risk_indicators": []
        }

    except requests.exceptions.Timeout:
        return {"ip": ip, "error": "API request timed out"}
    except requests.exceptions.ConnectionError:
        return {"ip": ip, "error": "Could not connect to ip-api.com"}
    except requests.exceptions.HTTPError as e:
        return {"ip": ip, "error": f"HTTP error: {e}"}
    except json.JSONDecodeError:
        return {"ip": ip, "error": "Invalid JSON response from API"}


def add_risk_indicators(enrichment: dict) -> dict:
    """Add risk assessment based on enrichment data."""
    if "error" in enrichment:
        return enrichment

    risks = []
    if enrichment.get("is_hosting"):
        risks.append("Hosting/Cloud provider — commonly used for attack infrastructure")
    if enrichment.get("is_proxy"):
        risks.append("Proxy/VPN detected — may be used to anonymise malicious activity")
    if enrichment.get("is_mobile"):
        risks.append("Mobile network — may indicate compromised mobile device")

    enrichment["risk_indicators"] = risks
    enrichment["risk_level"] = "HIGH" if len(risks) >= 2 else ("MEDIUM" if risks else "LOW")

    return enrichment


def main():
    if len(sys.argv) != 2:
        print("Usage: python log_enricher.py <log_file_path>")
        print("Example: python log_enricher.py sample_logs/firewall.log")
        sys.exit(1)

    log_file_path = sys.argv[1]

    print("=" * 60)
    print("  Log Enricher — IP Extraction & Threat Intelligence")
    print("=" * 60)
    print(f"\n[*] Parsing log file: {log_file_path}")

    # Extract unique public IPs
    public_ips = extract_public_ips(log_file_path)

    if not public_ips:
        print("[!] No public IP addresses found in the log file.")
        sys.exit(0)

    print(f"[*] Found {len(public_ips)} unique public IP(s)")
    print("[*] Enriching IPs with threat intelligence from ip-api.com...\n")

    # Enrich each IP and build results dictionary
    results = {}
    for ip in sorted(public_ips):
        print(f"  Querying: {ip}...", end=" ")
        enrichment = enrich_ip(ip)
        enrichment = add_risk_indicators(enrichment)
        results[ip] = enrichment

        if "error" in enrichment:
            print(f"ERROR: {enrichment['error']}")
        else:
            print(f"{enrichment['country']} | {enrichment['isp']} | Risk: {enrichment['risk_level']}")

    # Print formatted JSON output
    print("\n" + "=" * 60)
    print("  Enrichment Results (JSON)")
    print("=" * 60)
    print(json.dumps(results, indent=2))

    # Print summary
    print("\n" + "=" * 60)
    print("  Summary")
    print("=" * 60)
    high_risk = sum(1 for r in results.values() if r.get("risk_level") == "HIGH")
    medium_risk = sum(1 for r in results.values() if r.get("risk_level") == "MEDIUM")
    low_risk = sum(1 for r in results.values() if r.get("risk_level") == "LOW")
    errors = sum(1 for r in results.values() if "error" in r)
    print(f"  Total IPs analysed: {len(results)}")
    print(f"  High Risk: {high_risk} | Medium Risk: {medium_risk} | Low Risk: {low_risk} | Errors: {errors}")


if __name__ == "__main__":
    main()
