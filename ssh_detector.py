import subprocess
import re
import time
import sqlite3
from collections import defaultdict, deque


# Detection qaydaları
THRESHOLD = 5
WINDOW = 60

# Hər IP üçün failed login vaxtlarını saxlayırıq
failed_attempts = defaultdict(deque)


def save_alert(source_ip, count):

    # Database-ə qoşuluruq
    conn = sqlite3.connect("alerts.db")
    cursor = conn.cursor()

    # Alert məlumatını database-ə yazırıq
    cursor.execute("""
        INSERT INTO alerts
        (timestamp, source_ip, destination_ip,
         attack_type, severity, description)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        time.strftime("%Y-%m-%d %H:%M:%S"),
        source_ip,
        "192.168.1.101",
        "SSH_BRUTE_FORCE",
        "HIGH",
        f"{count} failed SSH login attempts within {WINDOW} seconds"
    ))

    # Dəyişiklikləri yadda saxla
    conn.commit()

    # Database bağlantısını bağla
    conn.close()

    print("[+] Alert saved to alerts.db")


def monitor_ssh():

    # SSH loglarını real-time oxuyuruq
    process = subprocess.Popen(
        ["journalctl", "-u", "ssh", "-f", "-o", "cat"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

    print("[*] SSH Brute Force Detector started...")
    print(f"[*] Threshold: {THRESHOLD} failed attempts / {WINDOW} seconds")

    # Yeni log sətrlərini oxuyuruq
    for line in process.stdout:

        line = line.strip()

        # Uğursuz SSH login deyilsə, keç
        if "Failed password" not in line:
            continue

        # Logdan source IP-ni çıxar
        match = re.search(
            r"from (\d+\.\d+\.\d+\.\d+)",
            line
        )

        if not match:
            continue

        source_ip = match.group(1)

        # İndiki vaxt
        now = time.time()

        # Bu IP-nin failed login vaxtını saxla
        failed_attempts[source_ip].append(now)

        # 60 saniyədən köhnə cəhdləri sil
        while failed_attempts[source_ip]:

            if now - failed_attempts[source_ip][0] > WINDOW:
                failed_attempts[source_ip].popleft()
            else:
                break

        # Hazırkı cəhd sayı
        count = len(failed_attempts[source_ip])

        print(
            f"[SSH] Failed login from {source_ip} "
            f"| Count: {count}"
        )

        # Threshold keçilibsə alert
        if count >= THRESHOLD:

            print()
            print("=" * 50)
            print("🚨 SSH BRUTE FORCE DETECTED")
            print("=" * 50)
            print(f"Source IP : {source_ip}")
            print(f"Attempts  : {count}")
            print(f"Window    : {WINDOW} seconds")
            print("Severity  : HIGH")
            print("=" * 50)

            # Database-ə yaz
            save_alert(source_ip, count)

            print()

            # Sayğacı sıfırla
            failed_attempts[source_ip].clear()


if __name__ == "__main__":
    monitor_ssh()
