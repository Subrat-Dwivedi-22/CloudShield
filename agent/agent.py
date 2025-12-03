#!/usr/bin/env python3
import boto3
import json
import time
import re
import requests
import os
import subprocess

# --- CONFIGURATION ---
REGION = "ap-south-1"  # Ensure this matches your Lambda region
LAMBDA_NAME = "AgenticAIAnalyzer"
AUTH_LOG = "/var/log/auth.log"
AUDIT_LOG = "/var/log/audit/audit.log"

# --- AWS SETUP ---
lambda_client = boto3.client("lambda", region_name=REGION)

# --- REGEX PATTERNS ---
# 1. SSH Brute Force: Capture IP directly from log
SSH_FAIL_RE = re.compile(r"(Invalid user|authentication failure|PAM: Authentication failure|Connection closed by).*?(\d+\.\d+\.\d+\.\d+)")

# 2. Privilege Escalation: Capture TTY to resolve IP later
# Matches: "sudo: ubuntu : TTY=pts/0 ; ..."
SUDO_RE = re.compile(r"sudo:\s+(\S+)\s+:\s+TTY=(\S+)")

# 3. File Deletion: From auditd
DELETE_RE = re.compile(r"key=\"file-deletion\"")


def get_instance_id():
    """Fetches the EC2 Instance ID using IMDSv2"""
    try:
        token = requests.put(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            timeout=2
        ).text
        instance_id = requests.get(
            "http://169.254.169.254/latest/meta-data/instance-id",
            headers={"X-aws-ec2-metadata-token": token},
            timeout=2
        ).text
        return instance_id
    except Exception as e:
        print(f"[ERROR] Failed to get Instance ID: {e}")
        return "UNKNOWN"

instance_id = get_instance_id()
print(f"[TARGET] Instance ID: {instance_id}")


# --- STATE TRACKING ---
stats = {
    "failed_logins": 0,
    "sudo_attempts": 0,
    "files_deleted": 0
}
last_sent_time = time.time()
current_attacker_ip = "unknown"


def resolve_ip_from_tty(tty_device):
    """
    Runs 'who' command to find which IP is connected to a specific TTY (e.g. pts/0)
    """
    try:
        # Run 'who' to get list of sessions: "ubuntu pts/0 2025-11-27 12:00 (103.x.x.x)"
        output = subprocess.check_output(["who"], text=True)

        # tty_device might be "pts/0" or just "unknown"
        if "pts" not in tty_device:
            return None

        for line in output.splitlines():
            # If the line contains our TTY (e.g. "pts/0")
            if tty_device in line:
                # Extract IP using Regex: Matches content inside ()
                ip_match = re.search(r"\(([\d\.]+)\)", line)
                if ip_match:
                    return ip_match.group(1)
    except Exception as e:
        print(f"[WARN] IP Resolution failed: {e}")

    return None


def follow_files(file_paths):
    """Reads from multiple files simultaneously"""
    files = {}
    for path in file_paths:
        try:
            f = open(path, "r")
            f.seek(0, 2)
            files[path] = f
        except FileNotFoundError:
            print(f"[WARN] Log file not found: {path}")

    while True:
        has_data = False
        for path, f in files.items():
            line = f.readline()
            if line:
                yield path, line
                has_data = True
        if not has_data:
            time.sleep(0.1)


def send_report():
    global stats, current_attacker_ip, last_sent_time

    if sum(stats.values()) == 0:
        return

    payload = {
        "instance_id": instance_id,
        "source_ip": current_attacker_ip,
        "bytes_sent": 500,
        "packets": 10,
        "duration_s": 1,
        "dst_port": 22,
        "login_attempts": stats["failed_logins"],
        "failed_logins": stats["failed_logins"],
        "sudo_attempts": stats["sudo_attempts"],
        "files_deleted": stats["files_deleted"]
    }

    print(f"[REPORT] Sending: {json.dumps(payload)}")

    try:
        lambda_client.invoke(
            FunctionName=LAMBDA_NAME,
            InvocationType="Event",
            Payload=json.dumps(payload)
        )
    except Exception as e:
        print(f"[ERROR] Lambda Trigger Failed: {e}")

    stats = {k: 0 for k in stats}
    last_sent_time = time.time()


print("[AGENT v3] Monitoring started... (Tracking TTYs)")

try:
    for filepath, line in follow_files([AUTH_LOG, AUDIT_LOG]):
        line = line.strip()

        # 1. AUTH.LOG (SSH & Sudo)
        if filepath == AUTH_LOG:

            # A. Check SSH Brute Force
            ssh_match = SSH_FAIL_RE.search(line)
            if ssh_match:
                stats["failed_logins"] += 1
                current_attacker_ip = ssh_match.group(2)
                print(f"[DETECT] SSH Fail from {current_attacker_ip}")

            # B. Check Sudo Abuse
            sudo_match = SUDO_RE.search(line)
            if sudo_match:
                stats["sudo_attempts"] += 1
                user = sudo_match.group(1)
                tty = sudo_match.group(2) # e.g. pts/0
                print(f"[DETECT] Sudo by {user} on {tty}")

                # Resolve IP if currently unknown
                resolved_ip = resolve_ip_from_tty(tty)
                if resolved_ip:
                    current_attacker_ip = resolved_ip
                    print(f"   -> TRACED IP: {current_attacker_ip}")

        # 2. AUDIT.LOG (File Deletion)
        elif filepath == AUDIT_LOG:
            if DELETE_RE.search(line):
                stats["files_deleted"] += 1
                print(f"[DETECT] File Deletion Detected")

        # 3. Send Logic
        if time.time() - last_sent_time > 5 and sum(stats.values()) > 0:
            send_report()

except KeyboardInterrupt:
    print("\n[AGENT] Stopping...")

