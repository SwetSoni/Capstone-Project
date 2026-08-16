"""
VirusTotal IP Enrichment Script
Capstone Part 4 — Task 4

Queries the VirusTotal API v3 for threat intelligence on public IPs
extracted by log_enricher.py.

Usage:
    python virustotal_check.py <log_file_path>

Example:
    python virustotal_check.py sample_logs/firewall.log

Requires:
    VT_API_KEY environment variable set with your VirusTotal API key.
    See .env.example for setup.
"""

import os
import sys
import json
import time
import requests
from dotenv import load_dotenv
from log_enricher import extract_public_ips

# Load environment variables from .env file
load_dotenv()


def get_api_key() -> str:
    """
    Load the VirusTotal API key from the VT_API_KEY environment variable.
    Never hardcode the API key in source code.
    """
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        print("Error: VT_API_KEY environment variable is not set.")
        print("Set it in your .env file or export it:")
        print("  export VT_API_KEY=<API_KEY>")
        sys.exit(1)
    return api_key


def query_virustotal(ip: str, api_key: str) -> dict:
    """
    Query VirusTotal API v3 for threat intelligence on an IP address.

    Args:
        ip: The public IP address to query.
        api_key: The VirusTotal API key.

    Returns:
        Dictionary with VT analysis results.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)

        # Handle specific HTTP error codes
        if response.status_code == 401:
            return {"ip": ip, "error": "Invalid API key. Check your VT_API_KEY."}
        elif response.status_code == 429:
            return {"ip": ip, "error": "Rate limit exceeded. Free tier allows 4 requests/min. Wait and retry."}
        elif response.status_code == 404:
            return {"ip": ip, "error": f"IP address {ip} not found in VirusTotal database."}
        elif response.status_code != 200:
            return {"ip": ip, "error": f"HTTP {response.status_code}: {response.reason}"}

        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        last_analysis = attributes.get("last_analysis_date", "N/A")

        # Convert Unix timestamp to readable date if present
        if isinstance(last_analysis, int):
            from datetime import datetime
            last_analysis = datetime.utcfromtimestamp(last_analysis).strftime("%Y-%m-%d %H:%M:%S UTC")

        return {
            "ip": ip,
            "malicious_detections": stats.get("malicious", 0),
            "harmless_count": stats.get("harmless", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "undetected_count": stats.get("undetected", 0),
            "last_analysis_date": last_analysis,
            "total_vendors": sum(stats.values()) if stats else 0,
            "country": attributes.get("country", "Unknown"),
            "as_owner": attributes.get("as_owner", "Unknown"),
        }

    except requests.exceptions.Timeout:
        return {"ip": ip, "error": "Request timed out. VirusTotal may be slow or unreachable."}
    except requests.exceptions.ConnectionError:
        return {"ip": ip, "error": "Could not connect to VirusTotal API. Check your internet connection."}
    except json.JSONDecodeError:
        return {"ip": ip, "error": "Invalid JSON response from VirusTotal."}
    except Exception as e:
        return {"ip": ip, "error": f"Unexpected error: {str(e)}"}


def main():
    if len(sys.argv) != 2:
        print("Usage: python virustotal_check.py <log_file_path>")
        print("Example: python virustotal_check.py sample_logs/firewall.log")
        sys.exit(1)

    log_file_path = sys.argv[1]
    api_key = get_api_key()

    print("=" * 65)
    print("  VirusTotal IP Enrichment")
    print("=" * 65)

    # Extract public IPs from log file (reuse log_enricher functionality)
    print(f"\n[*] Extracting public IPs from: {log_file_path}")
    public_ips = extract_public_ips(log_file_path)

    if not public_ips:
        print("[!] No public IP addresses found in the log file.")
        sys.exit(0)

    print(f"[*] Found {len(public_ips)} unique public IP(s)")
    print("[*] Querying VirusTotal API v3...\n")

    results = {}
    for i, ip in enumerate(sorted(public_ips)):
        print(f"  [{i+1}/{len(public_ips)}] Querying: {ip}...", end=" ")
        result = query_virustotal(ip, api_key)
        results[ip] = result

        if "error" in result:
            print(f"ERROR: {result['error']}")
        else:
            detections = result["malicious_detections"]
            total = result["total_vendors"]
            status = "⚠ MALICIOUS" if detections > 0 else "✓ CLEAN"
            print(f"{status} ({detections}/{total} vendors flagged)")

        # Respect rate limit: free tier = 4 requests/minute
        if i < len(public_ips) - 1:
            print("    (waiting 15s for rate limit...)")
            time.sleep(15)

    # Print formatted JSON output
    print("\n" + "=" * 65)
    print("  VirusTotal Results (JSON)")
    print("=" * 65)
    print(json.dumps(results, indent=2))

    # Print summary table
    print("\n" + "=" * 65)
    print(f"  {'IP':<18} {'Malicious':<12} {'Harmless':<12} {'Last Analysis'}")
    print("-" * 65)
    for ip, data in results.items():
        if "error" in data:
            print(f"  {ip:<18} {'ERROR':<12} {'':<12} {data['error']}")
        else:
            print(f"  {ip:<18} {data['malicious_detections']:<12} {data['harmless_count']:<12} {data['last_analysis_date']}")


if __name__ == "__main__":
    main()
