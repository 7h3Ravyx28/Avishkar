import re
import os
import argparse
import ipaddress
import time
import json
import csv
import logging
from collections import Counter
from tabulate import tabulate
from colorama import Fore, Style

# GeoIP2 for location lookup (optional)
try:
    import geoip2.database
except ImportError:
    geoip2 = None

# Configure logging
logging.basicConfig(
    format="[%(levelname)s] %(message)s",
    level=logging.INFO
)


def read_logs(path):
    """Read and parse SSH login logs."""
    if not os.path.exists(path):
        logging.error(f"Log file not found: {path}")
        return []

    pattern = re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*(Failed|Accepted) password for (\w+) from ([\d.]+)'
    )
    events = []

    with open(path, "r", encoding="utf-8") as log:
        for line in log:
            match = pattern.search(line)
            if match:
                time_stamp, status, user, ip = match.groups()

                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue  # skip invalid IPs

                events.append({
                    "time": time_stamp,
                    "status": status,
                    "user": user,
                    "ip": ip
                })

    return events


def count_failed(events):
    """Count failed login attempts grouped by IP."""
    return Counter(e["ip"] for e in events if e["status"] == "Failed")


def lookup_ip(ip, reader):
    """Resolve IP to country (if GeoIP DB available)."""
    if not geoip2 or not reader:
        return "Unknown"
    try:
        resp = reader.city(ip)
        return resp.country.name or "Unknown"
    except Exception:
        return "Unknown"


def build_report(failed, threshold=5, geoip_db=None):
    """Generate a threat summary table."""
    table = []
    reader = None

    if geoip_db and geoip2:
        if os.path.exists(geoip_db):
            reader = geoip2.database.Reader(geoip_db)
        else:
            logging.warning(f"GeoIP DB not found: {geoip_db}, skipping location lookup.")

    for ip, count in failed.items():
        severity = "High" if count > threshold else "Medium"
        color = Fore.RED if severity == "High" else Fore.YELLOW
        location = lookup_ip(ip, reader)
        table.append([ip, count, color + severity + Style.RESET_ALL, location])

    return table


def export_report(report, output_format, filename):
    """Export the report to CSV or JSON."""
    if output_format == "csv":
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Failed Attempts", "Severity", "Location"])
            for row in report:
                writer.writerow([row[0], row[1], row[2].strip(Fore.RED + Fore.YELLOW + Style.RESET_ALL), row[3]])
        logging.info(f"Report exported to {filename}")

    elif output_format == "json":
        json_data = [
            {"ip": row[0], "failed_attempts": row[1], "severity": row[2], "location": row[3]}
            for row in report
        ]
        with open(filename, "w") as f:
            json.dump(json_data, f, indent=4)
        logging.info(f"Report exported to {filename}")


def watch_logs(log_path, threshold, geoip_db, interval=10):
    """Watch log file in real-time for suspicious activity."""
    logging.info("Starting log watch mode...")
    last_size = 0
    while True:
        current_size = os.path.getsize(log_path)
        if current_size > last_size:  # log file updated
            events = read_logs(log_path)
            failed = count_failed(events)
            table = build_report(failed, threshold, geoip_db)
            if table:
                print(Fore.CYAN + "\n[+] Live Threat Report:\n" + Style.RESET_ALL)
                print(tabulate(table, headers=["IP", "Failed Attempts", "Severity", "Location"], tablefmt="pretty"))
        last_size = current_size
        time.sleep(interval)


def run():
    print(Fore.CYAN + "\n=== Avishkar - Mini Threat Hunting Tool ===\n" + Style.RESET_ALL)

    parser = argparse.ArgumentParser(description="Analyze SSH login logs for failed login attempts.")
    parser.add_argument("--log", required=True, help="Path to log file (e.g. logs/auth.log)")
    parser.add_argument("--geoip", help="Path to GeoLite2-City.mmdb (optional)")
    parser.add_argument("--threshold", type=int, default=5, help="Threshold for high severity detection")
    parser.add_argument("--export", choices=["csv", "json"], help="Export report format")
    parser.add_argument("--output", help="Output file name (used with --export)")
    parser.add_argument("--watch", action="store_true", help="Enable real-time log monitoring")
    args = parser.parse_args()

    if args.watch:
        watch_logs(args.log, args.threshold, args.geoip)
        return

    events = read_logs(args.log)
    logging.info(f"Found {len(events)} login events")

    failed = count_failed(events)
    if failed:
        table = build_report(failed, threshold=args.threshold, geoip_db=args.geoip)
        print(Fore.CYAN + "\n[+] Threat Report:\n" + Style.RESET_ALL)
        print(tabulate(table, headers=["IP", "Failed Attempts", "Severity", "Location"], tablefmt="pretty"))

        if args.export and args.output:
            export_report(table, args.export, args.output)
    else:
        print(Fore.GREEN + "[+] No failed login attempts detected!" + Style.RESET_ALL)


if __name__ == "__main__":
    run()
