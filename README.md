# Python Intrusion Detection System (IDS)

A Python-based Intrusion Detection System built for practical cybersecurity and SOC/Blue Team learning.

## Features

- TCP SYN Port Scan Detection
- SSH Brute Force Detection
- Real-time Security Alerts
- SQLite Alert Storage
- Alert Cooldown

## Technologies

- Python 3
- Scapy
- SQLite
- Linux
- Nmap

## Detection Rules

### Port Scan
Detects 10 unique destination ports targeted by the same source IP within 10 seconds.

### SSH Brute Force
Detects 5 failed SSH login attempts from the same source IP within 60 seconds.

## Usage

Start the IDS:

```bash
sudo python3 ids.py
