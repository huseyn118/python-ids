from scapy.all import sniff, IP, TCP
from collections import defaultdict
import sqlite3
from datetime import datetime
import time


# -----------------------------
# Configuration
# -----------------------------

TIME_WINDOW = 10
PORT_THRESHOLD = 10
ALERT_COOLDOWN = 30


# -----------------------------
# Database
# -----------------------------

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


# -----------------------------
# Detection memory
# -----------------------------

scan_tracker = defaultdict(list)

last_alert = {}


# -----------------------------
# Alert function
# -----------------------------

def create_alert(source_ip, destination_ip, attack_type,
                 severity, description):

    current_time = time.time()

    alert_key = (source_ip, destination_ip, attack_type)

    # Prevent duplicate alerts
    if alert_key in last_alert:

        if current_time - last_alert[alert_key] < ALERT_COOLDOWN:
            return

    last_alert[alert_key] = current_time

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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


# -----------------------------
# Packet analysis
# -----------------------------

def analyze_packet(packet):

    if not packet.haslayer(IP):
        return

    if not packet.haslayer(TCP):
        return

    flags = str(packet[TCP].flags)

    # We only analyze SYN packets
    if flags != "S":
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    destination_port = packet[TCP].dport

    current_time = time.time()

    # Store this SYN attempt
    scan_tracker[source_ip].append(
        (current_time, destination_port)
    )

    # Remove old events
    scan_tracker[source_ip] = [
        (timestamp, port)
        for timestamp, port in scan_tracker[source_ip]
        if current_time - timestamp <= TIME_WINDOW
    ]

    # Count unique ports
    unique_ports = {
        port
        for timestamp, port in scan_tracker[source_ip]
    }

    # Port scan detection
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

        # Reset after detection
        scan_tracker[source_ip].clear()


# -----------------------------
# Start IDS
# -----------------------------

print("[*] IDS started")
print("[*] Interface: enp0s3")
print("[*] Detection: TCP SYN Port Scan")
print(
    f"[*] Threshold: {PORT_THRESHOLD} ports "
    f"/ {TIME_WINDOW} seconds"
)

sniff(
    iface="enp0s3",
    prn=analyze_packet,
    store=False
)
