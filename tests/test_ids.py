import json
from pathlib import Path

from src.ids import (
    analyze_events,
    detect_brute_force,
    detect_port_scans,
    detect_traffic_anomalies,
    load_events,
    save_report,
)


def test_port_scan_detection():
    events = [
        {
            "source_ip": "192.168.1.50",
            "destination_port": 21,
        },
        {
            "source_ip": "192.168.1.50",
            "destination_port": 22,
        },
        {
            "source_ip": "192.168.1.50",
            "destination_port": 23,
        },
        {
            "source_ip": "192.168.1.50",
            "destination_port": 25,
        },
        {
            "source_ip": "192.168.1.50",
            "destination_port": 53,
        },
    ]

    alerts = detect_port_scans(events)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "PORT_SCAN"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["source_ip"] == "192.168.1.50"


def test_brute_force_detection():
    events = [
        {
            "source_ip": "10.0.0.25",
            "event_type": "AUTH_FAILURE",
        },
        {
            "source_ip": "10.0.0.25",
            "event_type": "AUTH_FAILURE",
        },
        {
            "source_ip": "10.0.0.25",
            "event_type": "AUTH_FAILURE",
        },
        {
            "source_ip": "10.0.0.25",
            "event_type": "AUTH_FAILURE",
        },
        {
            "source_ip": "10.0.0.25",
            "event_type": "AUTH_FAILURE",
        },
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "BRUTE_FORCE"
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["details"]["failed_attempts"] == 5


def test_traffic_spike_detection():
    events = [
        {
            "source_ip": "172.16.0.15",
            "bytes": 3000,
        },
        {
            "source_ip": "172.16.0.15",
            "bytes": 2000,
        },
    ]

    alerts = detect_traffic_anomalies(events)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "TRAFFIC_SPIKE"
    assert alerts[0]["severity"] == "MEDIUM"
    assert alerts[0]["details"]["total_bytes"] == 5000


def test_no_alerts_for_normal_traffic():
    events = [
        {
            "source_ip": "192.168.1.20",
            "destination_port": 443,
            "bytes": 500,
        },
        {
            "source_ip": "192.168.1.21",
            "destination_port": 443,
            "bytes": 400,
        },
    ]

    alerts = analyze_events(events)

    assert alerts == []


def test_analyze_events_detects_multiple_attacks():
    events = [
        {
            "source_ip": "192.168.1.50",
            "destination_port": 21,
        },
        {
            "source_ip": "192.168.1.50",
            "destination_port": 22,
        },
        {
            "source_ip": "192.168.1.50",
            "destination_port": 23,
        },
        {
            "source_ip": "192.168.1.50",
            "destination_port": 25,
        },
        {
            "source_ip": "192.168.1.50",
            "destination_port": 53,
        },
        {
            "source_ip": "10.0.0.25",
            "event_type": "AUTH_FAILURE",
        },
        {
            "source_ip": "10.0.0.25",
            "event_type": "AUTH_FAILURE",
        },
        {
            "source_ip": "10.0.0.25",
            "event_type": "AUTH_FAILURE",
        },
        {
            "source_ip": "10.0.0.25",
            "event_type": "AUTH_FAILURE",
        },
        {
            "source_ip": "10.0.0.25",
            "event_type": "AUTH_FAILURE",
        },
        {
            "source_ip": "172.16.0.15",
            "bytes": 6000,
        },
    ]

    alerts = analyze_events(events)

    assert len(alerts) == 3

    alert_types = {
        alert["alert_type"]
        for alert in alerts
    }

    assert "PORT_SCAN" in alert_types
    assert "BRUTE_FORCE" in alert_types
    assert "TRAFFIC_SPIKE" in alert_types


def test_load_events(tmp_path):
    event_file = tmp_path / "events.json"

    events = [
        {
            "source_ip": "192.168.1.10",
            "destination_port": 443,
            "bytes": 100,
        }
    ]

    event_file.write_text(json.dumps(events))

    loaded_events = load_events(str(event_file))

    assert loaded_events == events


def test_load_invalid_json(tmp_path):
    event_file = tmp_path / "invalid.json"

    event_file.write_text("{invalid json")

    loaded_events = load_events(str(event_file))

    assert loaded_events == []


def test_save_report(tmp_path, monkeypatch):
    report_directory = tmp_path / "reports"
    report_file = report_directory / "alerts.json"

    monkeypatch.setattr(
        "src.ids.REPORT_DIRECTORY",
        report_directory
    )

    monkeypatch.setattr(
        "src.ids.REPORT_FILE",
        report_file
    )

    alerts = [
        {
            "timestamp": "2026-09-28T13:00:00",
            "alert_type": "PORT_SCAN",
            "severity": "HIGH",
            "source_ip": "192.168.1.50",
            "description": "Test alert",
            "details": {
                "unique_ports": 5
            },
        }
    ]

    save_report(alerts)

    assert report_file.exists()

    report = json.loads(
        report_file.read_text()
    )

    assert report["total_alerts"] == 1
    assert report["alerts"][0]["alert_type"] == "PORT_SCAN"
