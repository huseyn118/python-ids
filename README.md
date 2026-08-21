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
## Detection Results

### Lab Screenshot 1
![Lab Screenshot 1](VirtualBox_kali_21_08_2026_01_01_27.png)

### Lab Screenshot 2
![Lab Screenshot 2](VirtualBox_kali_21_08_2026_01_14_25.png)

### Lab Screenshot 3
![Lab Screenshot 3](VirtualBox_kali_21_08_2026_17_39_37.png)

### Lab Screenshot 4
![Lab Screenshot 4](VirtualBox_kali_21_08_2026_17_47_31.png)

### Lab Screenshot 5
![Lab Screenshot 5](VirtualBox_kali_21_08_2026_18_03_26.png)
