from scapy.all import sniff, IP, TCP
from collections import defaultdict, deque
import sqlite3
from datetime import datetime
import time
import subprocess
import re
import threading


# ============================================================
# CONFIGURATION
# ============================================================

TIME_WINDOW = 10
PORT_THRESHOLD = 10
ALERT_COOLDOWN = 30

SSH_WINDOW = 60
SSH_THRESHOLD = 5


# ============================================================
# DATABASE
# ============================================================

def create_database():

    db = sqlite3.connect("alerts.db")

    cursor = db.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        attack_type TEXT,
        severity TEXT,
        description TEXT
    )
    """)

    db.commit()
    db.close()


# ============================================================
# DETECTION MEMORY
# ============================================================

scan_tracker = defaultdict(list)

ssh_tracker = defaultdict(deque)

last_alert = {}


# ============================================================
# ALERT FUNCTION
# ============================================================

def create_alert(source_ip, destination_ip, attack_type,
                 severity, description):

    current_time = time.time()

    alert_key = (
        source_ip,
        destination_ip,
        attack_type
    )

    # Prevent duplicate alerts
    if alert_key in last_alert:

        if current_time - last_alert[alert_key] < ALERT_COOLDOWN:
            return

    last_alert[alert_key] = current_time

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # Open database connection
    db = sqlite3.connect("alerts.db")

    cursor = db.cursor()

    # Save alert
    cursor.execute("""
    INSERT INTO alerts (
        timestamp,
        source_ip,
        destination_ip,
        attack_type,
        severity,
        description
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        source_ip,
        destination_ip,
        attack_type,
        severity,
        description
    ))

    db.commit()
    db.close()

    # Display alert
    print()
    print("=" * 60)
    print("🚨 SECURITY ALERT")
    print(f"Time        : {timestamp}")
    print(f"Source IP   : {source_ip}")
    print(f"Target IP   : {destination_ip}")
    print(f"Attack      : {attack_type}")
    print(f"Severity    : {severity}")
    print(f"Description : {description}")
    print("=" * 60)
    print()


# ============================================================
# PORT SCAN DETECTION
# ============================================================

def analyze_packet(packet):

    # We need IP layer
    if not packet.haslayer(IP):
        return

    # We need TCP layer
    if not packet.haslayer(TCP):
        return

    flags = str(packet[TCP].flags)

    # Only analyze SYN packets
    if flags != "S":
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    destination_port = packet[TCP].dport

    current_time = time.time()

    # Store SYN attempt
    scan_tracker[source_ip].append(
        (current_time, destination_port)
    )

    # Remove events older than TIME_WINDOW
    scan_tracker[source_ip] = [
        (timestamp, port)
        for timestamp, port
        in scan_tracker[source_ip]
        if current_time - timestamp <= TIME_WINDOW
    ]

    # Get unique destination ports
    unique_ports = {
        port
        for timestamp, port
        in scan_tracker[source_ip]
    }

    # Detect port scan
    if len(unique_ports) >= PORT_THRESHOLD:

        description = (
            f"{len(unique_ports)} unique ports targeted "
            f"within {TIME_WINDOW} seconds"
        )

        create_alert(
            source_ip,
            destination_ip,
            "PORT_SCAN",
            "HIGH",
            description
        )

        # Reset tracker
        scan_tracker[source_ip].clear()


# ============================================================
# SSH BRUTE FORCE DETECTION
# ============================================================

def monitor_ssh():

    # Follow only NEW SSH log entries
    process = subprocess.Popen(
        [
            "journalctl",
            "-u",
            "ssh",
            "-n",
            "0",
            "-f",
            "-o",
            "cat"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

    print("[*] SSH Brute Force Detection enabled")
    print(
        f"[*] SSH Threshold: "
        f"{SSH_THRESHOLD} failed attempts / "
        f"{SSH_WINDOW} seconds"
    )

    # Read new log lines
    for line in process.stdout:

        line = line.strip()

        # Ignore unrelated SSH events
        if "Failed password" not in line:
            continue

        # Extract source IP
        match = re.search(
            r"from (\d+\.\d+\.\d+\.\d+)",
            line
        )

        if not match:
            continue

        source_ip = match.group(1)

        current_time = time.time()

        # Save failed login time
        ssh_tracker[source_ip].append(
            current_time
        )

        # Remove old attempts
        while ssh_tracker[source_ip]:

            if (
                current_time -
                ssh_tracker[source_ip][0]
                > SSH_WINDOW
            ):
                ssh_tracker[source_ip].popleft()

            else:
                break

        # Count recent attempts
        count = len(
            ssh_tracker[source_ip]
        )

        print(
            f"[SSH] Failed login from "
            f"{source_ip} | Count: {count}"
        )

        # Detect brute force
        if count >= SSH_THRESHOLD:

            description = (
                f"{count} failed SSH login attempts "
                f"within {SSH_WINDOW} seconds"
            )

            create_alert(
                source_ip,
                "192.168.1.101",
                "SSH_BRUTE_FORCE",
                "HIGH",
                description
            )

            # Reset after detection
            ssh_tracker[source_ip].clear()


# ============================================================
# START IDS
# ============================================================

create_database()

print()
print("=" * 60)
print("        PYTHON INTRUSION DETECTION SYSTEM")
print("=" * 60)

print("[*] IDS started")
print("[*] Interface: enp0s3")

print(
    f"[*] Port Scan: "
    f"{PORT_THRESHOLD} ports / "
    f"{TIME_WINDOW} seconds"
)

print(
    f"[*] SSH Brute Force: "
    f"{SSH_THRESHOLD} attempts / "
    f"{SSH_WINDOW} seconds"
)

print("[*] Database: alerts.db")
print("=" * 60)
print()


# ============================================================
# START SSH DETECTOR IN BACKGROUND
# ============================================================

ssh_thread = threading.Thread(
    target=monitor_ssh,
    daemon=True
)

ssh_thread.start()


# ============================================================
# START NETWORK PACKET CAPTURE
# ============================================================

sniff(
    iface="enp0s3",
    prn=analyze_packet,
    store=False
)
