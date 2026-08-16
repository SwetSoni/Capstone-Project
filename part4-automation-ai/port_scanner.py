"""
Multithreaded Port Scanner with Banner Grabbing
Capstone Part 4 — Task 1

Usage:
    python port_scanner.py <target_ip> <start_port> <end_port>

Example:
    python port_scanner.py 192.168.56.20 1 1024
"""

import sys
import socket
import threading
from datetime import datetime

# Shared list to store results from all threads
open_ports = []

# Thread lock to prevent race conditions when multiple threads
# write to the shared open_ports list simultaneously. Without this,
# concurrent list.append() calls could corrupt the list or lose results.
lock = threading.Lock()

# Default timeout in seconds for each connection attempt.
# 1 second is sufficient for local network scanning — long enough to
# detect open ports but short enough to keep the scan fast. Increase
# for scanning over WAN/VPN where latency is higher.
DEFAULT_TIMEOUT = 1


def scan_port(target: str, port: int, timeout: float = DEFAULT_TIMEOUT):
    """
    Attempt a TCP connection to target:port and grab the service banner.

    Args:
        target: The IP address to scan.
        port: The port number to scan.
        timeout: Connection timeout in seconds.
    """
    try:
        # Create a TCP socket (AF_INET = IPv4, SOCK_STREAM = TCP)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Attempt TCP connection (three-way handshake)
        result = sock.connect_ex((target, port))

        if result == 0:
            # Port is open — attempt banner grabbing
            banner = ""
            try:
                # Send a generic probe (carriage return + newline) to trigger
                # a service response. Many services (FTP, SSH, SMTP, HTTP)
                # respond with a banner/version string when they receive input.
                sock.send(b"\r\n")

                # Receive up to 1024 bytes of the banner response.
                # decode with errors='ignore' to handle non-UTF-8 binary
                # responses without crashing the script.
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            except (socket.timeout, ConnectionResetError, OSError):
                # Banner grab failed — the port is open but the service
                # didn't respond to our probe (common for encrypted services)
                banner = "No banner received"

            # Acquire the lock before writing to the shared list to prevent
            # race conditions between concurrent threads
            with lock:
                open_ports.append({
                    "port": port,
                    "state": "open",
                    "banner": banner if banner else "No banner received"
                })

        sock.close()

    except socket.timeout:
        # Connection timed out — port is likely filtered by a firewall
        pass
    except ConnectionRefusedError:
        # Connection refused — port is closed (RST received)
        pass
    except OSError as e:
        # Other OS-level network errors (e.g., network unreachable)
        pass


def main():
    # Parse command-line arguments
    if len(sys.argv) != 4:
        print("Usage: python port_scanner.py <target_ip> <start_port> <end_port>")
        print("Example: python port_scanner.py 192.168.56.20 1 1024")
        sys.exit(1)

    target = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])

    # Validate inputs
    try:
        socket.inet_aton(target)  # Validate IP address format
    except socket.error:
        print(f"Error: '{target}' is not a valid IP address.")
        sys.exit(1)

    if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
        print("Error: Port range must be between 1 and 65535.")
        sys.exit(1)

    if start_port > end_port:
        print("Error: Start port must be less than or equal to end port.")
        sys.exit(1)

    print("=" * 65)
    print(f"  Port Scanner — Target: {target}")
    print(f"  Port Range: {start_port}-{end_port}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)
    print()

    # Create and start threads for concurrent scanning
    threads = []
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(target, port))
        threads.append(thread)
        thread.start()

        # Limit concurrent threads to avoid overwhelming the target
        # or running out of file descriptors on the scanner
        if len(threads) >= 100:
            for t in threads:
                t.join()
            threads = []

    # Wait for any remaining threads to complete
    for t in threads:
        t.join()

    # Sort results by port number for clean output
    open_ports.sort(key=lambda x: x["port"])

    # Print formatted results table
    if open_ports:
        print(f"{'Port':<10} {'State':<10} {'Banner'}")
        print("-" * 65)
        for entry in open_ports:
            # Truncate long banners for table readability
            banner_display = entry["banner"][:45] if len(entry["banner"]) > 45 else entry["banner"]
            print(f"{entry['port']:<10} {entry['state']:<10} {banner_display}")
        print("-" * 65)
        print(f"\n{len(open_ports)} open port(s) found on {target}")
    else:
        print(f"No open ports found on {target} in range {start_port}-{end_port}")

    print(f"\nScan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
