# Network Intrusion Detection System

A Python-based Network Intrusion Detection System (NIDS) designed to identify suspicious network activity using rule-based detection techniques.

The system analyzes network events from JSON data and generates security alerts for potential port scanning, brute-force authentication attacks, and abnormal traffic volumes.

---

## Features

* Port scan detection
* Brute-force authentication detection
* Traffic anomaly detection
* Security alert generation
* HIGH and MEDIUM severity classification
* JSON security reports
* Security event logging
* Command-line interface
* Automated unit tests
* Invalid JSON handling
* Clean-traffic detection
* Multiple attack detection in a single scan

---

## Architecture

```text
                 Network Events
                       |
                       v
                JSON Event Data
                       |
                       v
              +----------------+
              |   IDS Engine   |
              +----------------+
                       |
          +------------+------------+
          |            |            |
          v            v            v
      Port Scan    Brute Force   Traffic Spike
      Detection    Detection     Detection
          |            |            |
          +------------+------------+
                       |
                       v
                Security Alerts
                       |
              +--------+--------+
              |                 |
              v                 v
          ids.log          alerts.json
```

---

## Detection Rules

### 1. Port Scan Detection

The system tracks destination ports contacted by each source IP address.

If a source IP contacts at least **5 unique destination ports**, the activity is classified as a potential port scan.

```text
Threshold: 5 unique ports
Severity: HIGH
Alert Type: PORT_SCAN
```

Example:

```text
Source IP: 192.168.1.50

Destination ports:
21
22
23
25
53
```

This generates a `PORT_SCAN` security alert.

---

### 2. Brute-Force Detection

The system counts failed authentication attempts from each source IP address.

If a source generates at least **5 authentication failures**, the system generates a potential brute-force alert.

```text
Threshold: 5 failed attempts
Severity: HIGH
Alert Type: BRUTE_FORCE
```

Example:

```text
Source IP: 10.0.0.25

Authentication failures:
1
2
3
4
5
```

This generates a `BRUTE_FORCE` security alert.

---

### 3. Traffic Spike Detection

The system calculates the total number of bytes associated with each source IP address.

If traffic reaches at least **5000 bytes**, the system generates a traffic anomaly alert.

```text
Threshold: 5000 bytes
Severity: MEDIUM
Alert Type: TRAFFIC_SPIKE
```

Example:

```text
Source IP: 172.16.0.15

Total traffic:
6000 bytes
```

This generates a `TRAFFIC_SPIKE` security alert.

---

## Project Structure

```text
network-intrusion-detection/
│
├── src/
│   ├── __init__.py
│   └── ids.py
│
├── tests/
│   └── test_ids.py
│
├── data/
│   └── sample_events.json
│
├── logs/
│   └── ids.log
│
├── reports/
│   └── alerts.json
│
├── .gitignore
├── pytest.ini
├── README.md
└── requirements.txt
```

---

## Requirements

* Python 3.10+
* Linux, macOS, or Windows
* pip
* Git

---

## Installation

Clone the repository:

```bash
git clone https://github.com/kingsley-jpg/Network-Intrusion-Detection.git
```

Enter the project directory:

```bash
cd Network-Intrusion-Detection
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate the virtual environment:

```bash
source venv/bin/activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

---

## Running the IDS

The project includes a simulated network-event dataset.

Run the IDS using:

```bash
python src/ids.py data/sample_events.json
```

Example output:

```text
[+] Loaded 11 network events.

=== NETWORK INTRUSION DETECTION RESULTS ===

[HIGH] PORT_SCAN | Source: 192.168.1.50
    Possible port scanning activity detected.
    unique_ports: 5
    ports: [21, 22, 23, 25, 53]

[HIGH] BRUTE_FORCE | Source: 10.0.0.25
    Possible brute-force authentication attack detected.
    failed_attempts: 5

[MEDIUM] TRAFFIC_SPIKE | Source: 172.16.0.15
    Unusually high traffic volume detected.
    total_bytes: 6000

Total alerts: 3

[+] Report saved to: reports/alerts.json
```

---

## Security Report

After the IDS completes its analysis, detected alerts are stored in:

```text
reports/alerts.json
```

The report contains:

* Report generation timestamp
* Total number of alerts
* Alert type
* Severity
* Source IP address
* Description
* Detection details

Example:

```json
{
    "generated_at": "2026-09-28T13:00:00",
    "total_alerts": 3,
    "alerts": [
        {
            "alert_type": "PORT_SCAN",
            "severity": "HIGH",
            "source_ip": "192.168.1.50"
        }
    ]
}
```

---

## Security Logging

Security events are written to:

```text
logs/ids.log
```

The log records events such as:

```text
ALERT | severity=HIGH | type=PORT_SCAN | source=192.168.1.50
```

and:

```text
SCAN_COMPLETED | events=11 | alerts=3
```

---

## Running Automated Tests

The project uses `pytest` for automated testing.

Run:

```bash
pytest -v
```

The test suite validates:

* Port scan detection
* Brute-force detection
* Traffic anomaly detection
* Normal traffic with no alerts
* Multiple simultaneous attack detections
* JSON event loading
* Invalid JSON handling
* Alert report generation

Expected result:

```text
8 passed
```

---

## Exit Codes

The IDS uses standard command-line exit codes.

| Exit Code | Meaning                         |
| --------- | ------------------------------- |
| `0`       | No suspicious activity detected |
| `1`       | Security alerts detected        |
| `2`       | Input or processing error       |

This allows the IDS to be integrated into shell scripts and other security automation tools.

Example:

```bash
python src/ids.py data/sample_events.json
echo $?
```

If suspicious activity is detected:

```text
1
```

---

## Example Attack Scenarios

The included dataset simulates three different types of suspicious behavior.

### Port Scan

```text
192.168.1.50
      |
      +----> Port 21
      +----> Port 22
      +----> Port 23
      +----> Port 25
      +----> Port 53
```

The source contacts five different destination ports and triggers a `PORT_SCAN` alert.

---

### Brute Force

```text
10.0.0.25
     |
     +----> Authentication failure
     +----> Authentication failure
     +----> Authentication failure
     +----> Authentication failure
     +----> Authentication failure
```

Five failed authentication attempts trigger a `BRUTE_FORCE` alert.

---

### Traffic Spike

```text
172.16.0.15
      |
      +----> 6000 bytes
```

The traffic exceeds the 5000-byte threshold and triggers a `TRAFFIC_SPIKE` alert.

---

## Sample Data

The project uses simulated network events rather than capturing traffic from external systems.

The sample dataset contains:

* TCP network events
* Source and destination IP addresses
* Source and destination ports
* Transferred bytes
* Authentication failure events
* Timestamps

Sample data is located at:

```text
data/sample_events.json
```

---

## Security Considerations

This project is designed for:

* Cybersecurity education
* Defensive security research
* Network monitoring experiments
* IDS development practice
* Security engineering portfolio development

The included network events are simulated.

Any testing against real networks, systems, or devices should only be performed where you have explicit authorization.

---

## Limitations

The current version uses rule-based analysis of JSON network events.

It does not currently provide:

* Real-time packet capture
* Deep packet inspection
* Encrypted traffic analysis
* Machine-learning-based anomaly detection
* Network flow reconstruction
* Distributed monitoring sensors
* Automatic incident response
* Advanced threat intelligence integration
* Full protocol analysis

The current implementation is therefore a lightweight educational IDS rather than a production enterprise IDS.

---

## Future Improvements

Possible future improvements include:

### Real-Time Packet Capture

Integrate packet-capture capabilities using tools such as Scapy.

### Machine Learning

Add machine-learning models for detecting unusual network behavior.

### Network Interface Monitoring

Allow the IDS to monitor an authorized local network interface in real time.

### Threat Intelligence

Integrate IP reputation and threat-intelligence feeds.

### Web Dashboard

Create a dashboard displaying:

* Active alerts
* Attack sources
* Alert severity
* Traffic statistics
* Historical events

### SIEM Integration

Forward alerts to security platforms such as SIEM systems.

### Automated Notifications

Add email, webhook, or messaging notifications for critical alerts.

### PCAP Analysis

Allow the IDS to analyze previously captured PCAP files.

---

## Technologies

* Python 3
* JSON
* Pytest
* Linux
* Git
* GitHub

---

## Learning Objectives

This project demonstrates practical knowledge of:

* Python programming
* Defensive cybersecurity
* Network security concepts
* Intrusion detection
* Security event analysis
* Rule-based detection
* Log management
* JSON data processing
* Automated testing
* Command-line application development
* Git/GitHub project management

---

## Author

**Kingsley Senyedji**

Computer Science Student
Cybersecurity / Ethical Hacking

GitHub:

https://github.com/kingsley-jpg

---

## Disclaimer

This project is intended for educational and defensive cybersecurity purposes.

Only analyze network traffic and systems that you own or have explicit authorization to monitor.
