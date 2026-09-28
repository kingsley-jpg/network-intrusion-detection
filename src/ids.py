import argparse
import json
import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# ============================================================
# Configuration
# ============================================================

PROJECT_ROOT = Path(__file__).parent.parent

LOG_DIRECTORY = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIRECTORY / "ids.log"

REPORT_DIRECTORY = PROJECT_ROOT / "reports"
REPORT_FILE = REPORT_DIRECTORY / "alerts.json"


# Detection thresholds
PORT_SCAN_THRESHOLD = 5
BRUTE_FORCE_THRESHOLD = 5
TRAFFIC_SPIKE_THRESHOLD = 5000


# ============================================================
# Logging
# ============================================================

def setup_logging() -> None:
    """Configure security event logging."""

    LOG_DIRECTORY.mkdir(exist_ok=True)

    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )


# ============================================================
# Alert Creation
# ============================================================

def create_alert(
    alert_type: str,
    severity: str,
    source_ip: str,
    description: str,
    details: dict
) -> dict:
    """Create a standardized security alert."""

    alert = {
        "timestamp": datetime.now().isoformat(),
        "alert_type": alert_type,
        "severity": severity,
        "source_ip": source_ip,
        "description": description,
        "details": details
    }

    logging.warning(
        f"ALERT | severity={severity} | "
        f"type={alert_type} | "
        f"source={source_ip} | "
        f"{description}"
    )

    return alert


# ============================================================
# Port Scan Detection
# ============================================================

def detect_port_scans(events: list[dict]) -> list[dict]:
    """Detect possible port scanning activity."""

    ports_by_ip = defaultdict(set)

    for event in events:
        source_ip = event.get("source_ip")
        destination_port = event.get("destination_port")

        if source_ip and destination_port:
            ports_by_ip[source_ip].add(destination_port)

    alerts = []

    for source_ip, ports in ports_by_ip.items():

        if len(ports) >= PORT_SCAN_THRESHOLD:

            alert = create_alert(
                alert_type="PORT_SCAN",
                severity="HIGH",
                source_ip=source_ip,
                description="Possible port scanning activity detected.",
                details={
                    "unique_ports": len(ports),
                    "ports": sorted(ports)
                }
            )

            alerts.append(alert)

    return alerts


# ============================================================
# Brute Force Detection
# ============================================================

def detect_brute_force(events: list[dict]) -> list[dict]:
    """Detect repeated failed authentication attempts."""

    failures_by_ip = defaultdict(int)

    for event in events:

        if event.get("event_type") == "AUTH_FAILURE":

            source_ip = event.get("source_ip")

            if source_ip:
                failures_by_ip[source_ip] += 1

    alerts = []

    for source_ip, failures in failures_by_ip.items():

        if failures >= BRUTE_FORCE_THRESHOLD:

            alert = create_alert(
                alert_type="BRUTE_FORCE",
                severity="HIGH",
                source_ip=source_ip,
                description="Possible brute-force authentication attack detected.",
                details={
                    "failed_attempts": failures
                }
            )

            alerts.append(alert)

    return alerts


# ============================================================
# Traffic Anomaly Detection
# ============================================================

def detect_traffic_anomalies(events: list[dict]) -> list[dict]:
    """Detect unusually high traffic volume from a source."""

    traffic_by_ip = defaultdict(int)

    for event in events:

        source_ip = event.get("source_ip")
        bytes_transferred = event.get("bytes", 0)

        if source_ip:

            traffic_by_ip[source_ip] += bytes_transferred

    alerts = []

    for source_ip, total_bytes in traffic_by_ip.items():

        if total_bytes >= TRAFFIC_SPIKE_THRESHOLD:

            alert = create_alert(
                alert_type="TRAFFIC_SPIKE",
                severity="MEDIUM",
                source_ip=source_ip,
                description="Unusually high traffic volume detected.",
                details={
                    "total_bytes": total_bytes
                }
            )

            alerts.append(alert)

    return alerts


# ============================================================
# Detection Engine
# ============================================================

def analyze_events(events: list[dict]) -> list[dict]:
    """Run all detection rules against network events."""

    alerts = []

    alerts.extend(detect_port_scans(events))
    alerts.extend(detect_brute_force(events))
    alerts.extend(detect_traffic_anomalies(events))

    return alerts


# ============================================================
# Report Generation
# ============================================================

def save_report(alerts: list[dict]) -> None:
    """Save detected alerts to a JSON report."""

    REPORT_DIRECTORY.mkdir(exist_ok=True)

    report = {
        "generated_at": datetime.now().isoformat(),
        "total_alerts": len(alerts),
        "alerts": alerts
    }

    with open(REPORT_FILE, "w") as file:
        json.dump(report, file, indent=4)

    print(f"\n[+] Report saved to: {REPORT_FILE}")


# ============================================================
# Display Results
# ============================================================

def display_alerts(alerts: list[dict]) -> None:
    """Display security alerts."""

    print("\n=== NETWORK INTRUSION DETECTION RESULTS ===\n")

    if not alerts:
        print("[+] No suspicious activity detected.")
        return

    for alert in alerts:

        print(
            f"[{alert['severity']}] "
            f"{alert['alert_type']} | "
            f"Source: {alert['source_ip']}"
        )

        print(f"    {alert['description']}")

        for key, value in alert["details"].items():
            print(f"    {key}: {value}")

        print()

    print(f"Total alerts: {len(alerts)}")


# ============================================================
# Load Events
# ============================================================

def load_events(file_path: str) -> list[dict]:
    """Load network events from a JSON file."""

    path = Path(file_path)

    if not path.exists():
        print(f"[ERROR] Event file not found: {file_path}")
        return []

    try:

        with open(path, "r") as file:
            events = json.load(file)

    except json.JSONDecodeError:
        print("[ERROR] Invalid JSON event file.")
        return []

    if not isinstance(events, list):
        print("[ERROR] Event file must contain a JSON list.")
        return []

    return events


# ============================================================
# CLI
# ============================================================

def main() -> int:
    """Main command-line interface."""

    setup_logging()

    parser = argparse.ArgumentParser(
        description="Network Intrusion Detection System"
    )

    parser.add_argument(
        "events",
        help="JSON file containing network events"
    )

    args = parser.parse_args()

    events = load_events(args.events)

    if not events:
        return 2

    print(f"[+] Loaded {len(events)} network events.")

    alerts = analyze_events(events)

    display_alerts(alerts)
    save_report(alerts)

    logging.info(
        f"SCAN_COMPLETED | "
        f"events={len(events)} | "
        f"alerts={len(alerts)}"
    )

    if alerts:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
