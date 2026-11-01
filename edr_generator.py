
import json
import random
import uuid
import hashlib
import os
import time
import argparse
from datetime import datetime, timezone

# ==========================================================
# KILLCHAIN AI - SYNTHETIC EDR LOG GENERATOR
# ==========================================================

HOSTS = [
    f"WS-{dept}-{i:03d}"
    for dept in ["FIN", "HR", "ENG", "SALES"]
    for i in range(10, 16)
] + [
    "SRV-DC-01",
    "SRV-FILE-01",
    "SRV-WEB-01",
    "SRV-DB-01"
]

USERS = [
    "admin", "rkumar", "asharma", "pmehta",
    "sgupta", "nverma", "svc_backup", "svc_sql"
]

BENIGN_PROCESSES = [
    "chrome.exe", "explorer.exe", "svchost.exe",
    "outlook.exe", "winword.exe", "excel.exe",
    "powershell.exe", "MsMpEng.exe", "notepad.exe"
]

MALICIOUS_ACTIVITIES = [
    {
        "name": "Suspicious PowerShell Execution",
        "technique": "T1059.001",
        "tactic": "Execution",
        "severity": "high",
        "action": "suspicious_process_execution"
    },
    {
        "name": "Command and Control Beaconing",
        "technique": "T1071.001",
        "tactic": "Command and Control",
        "severity": "high",
        "action": "suspicious_network_connection"
    },
    {
        "name": "Brute Force Login",
        "technique": "T1110",
        "tactic": "Credential Access",
        "severity": "medium",
        "action": "multiple_failed_logins"
    },
    {
        "name": "Registry Persistence",
        "technique": "T1547.001",
        "tactic": "Persistence",
        "severity": "high",
        "action": "registry_persistence"
    },
    {
        "name": "Ransomware-like File Changes",
        "technique": "T1486",
        "tactic": "Impact",
        "severity": "critical",
        "action": "mass_file_rename"
    }
]

SEVERITY = {
    "informational": 0,
    "low": 3,
    "medium": 5,
    "high": 8,
    "critical": 10
}

SUSPICIOUS_IPS = [
    "198.51.100.23",
    "203.0.113.57",
    "192.0.2.88"
]

BENIGN_DOMAINS = [
    "login.microsoftonline.com",
    "github.com",
    "teams.microsoft.com",
    "update.microsoft.com",
    "google.com"
]


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def make_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def base_event():
    host = random.choice(HOSTS)
    user = random.choice(USERS)

    return {
        "@timestamp": timestamp(),
        "event": {
            "id": str(uuid.uuid4()),
            "kind": "event",
            "category": ["process"],
            "type": ["info"],
            "action": "process_created",
            "severity": 0,
            "module": "edr",
            "dataset": "edr.telemetry"
        },
        "agent": {
            "id": make_hash(host)[:16],
            "name": "KillChainAI-EDR",
            "type": "edr",
            "version": "1.0"
        },
        "host": {
            "name": host,
            "ip": [f"10.10.{random.randint(1,4)}.{random.randint(10,250)}"],
            "os": {
                "type": "windows",
                "full": "Windows 11 Enterprise"
            }
        },
        "user": {
            "name": user,
            "domain": "CORP"
        }
    }


# ==========================================================
# BENIGN EVENTS
# ==========================================================

def generate_benign():

    event = base_event()

    activity = random.choice([
        "process", "network", "authentication",
        "file", "dns"
    ])

    if activity == "process":

        process = random.choice(BENIGN_PROCESSES)

        event["event"]["category"] = ["process"]
        event["process"] = {
            "name": process,
            "pid": random.randint(1000, 65000),
            "executable": f"C:\\Windows\\System32\\{process}",
            "hash": make_hash(process)
        }

    elif activity == "network":

        event["event"]["category"] = ["network"]
        event["event"]["action"] = "network_connection"

        event["destination"] = {
            "ip": f"203.0.113.{random.randint(1,254)}",
            "port": 443,
            "domain": random.choice(BENIGN_DOMAINS)
        }

        event["network"] = {
            "transport": "tcp",
            "direction": "outbound",
            "bytes": random.randint(500, 500000)
        }

    elif activity == "authentication":

        event["event"]["category"] = ["authentication"]
        success = random.random() < 0.95

        event["event"]["outcome"] = (
            "success" if success else "failure"
        )

        event["winlog"] = {
            "event_id": 4624 if success else 4625
        }

    elif activity == "file":

        event["event"]["category"] = ["file"]

        event["file"] = {
            "path": "C:\\Users\\Public\\Documents\\report.docx",
            "size": random.randint(100, 500000)
        }

    else:

        event["event"]["category"] = ["network"]
        event["event"]["action"] = "dns_query"

        event["dns"] = {
            "question": {
                "name": random.choice(BENIGN_DOMAINS),
                "type": "A"
            }
        }

    return event


# ==========================================================
# SIMULATED MALICIOUS EVENTS
# ==========================================================

def generate_malicious():

    event = base_event()

    activity = random.choice(MALICIOUS_ACTIVITIES)

    event["event"]["kind"] = "alert"
    event["event"]["category"] = ["intrusion_detection"]
    event["event"]["type"] = ["indicator", "denied"]
    event["event"]["action"] = activity["action"]
    event["event"]["severity"] = SEVERITY[activity["severity"]]

    event["threat"] = {
        "framework": "MITRE ATT&CK",
        "technique": {
            "id": [activity["technique"]],
            "name": [activity["name"]]
        },
        "tactic": {
            "name": [activity["tactic"]]
        }
    }

    event["rule"] = {
        "name": activity["name"],
        "severity": activity["severity"]
    }

    event["labels"] = {
        "synthetic": "true",
        "simulated_detection": "true"
    }

    # Add activity-specific representative telemetry.
    if activity["technique"] == "T1059.001":

        event["process"] = {
            "name": "powershell.exe",
            "pid": random.randint(1000, 65000),
            "parent": {"name": "winword.exe"},
            "command_line": "powershell.exe -NoProfile <SIMULATED>"
        }

    elif activity["technique"] == "T1071.001":

        event["event"]["category"] = ["network"]

        event["destination"] = {
            "ip": random.choice(SUSPICIOUS_IPS),
            "port": 443,
            "domain": "suspicious-example-c2.invalid"
        }

    elif activity["technique"] == "T1110":

        event["event"]["category"] = ["authentication"]
        event["event"]["outcome"] = "failure"

        event["winlog"] = {
            "event_id": 4625,
            "failed_count_5min": random.randint(25, 120)
        }

    elif activity["technique"] == "T1547.001":

        event["event"]["category"] = ["registry"]

        event["registry"] = {
            "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "data": "<SIMULATED_ENTRY>"
        }

    elif activity["technique"] == "T1486":

        event["event"]["category"] = ["file"]

        event["file"] = {
            "extension": "locked",
            "files_renamed_60s": random.randint(200, 4000)
        }

    return event


# ==========================================================
# MAIN GENERATOR
# ==========================================================

def generate_dataset(size_gb, alert_ratio, output):

    target_size = int(size_gb * 1_000_000_000)

    total_events = 0
    malicious_events = 0
    written_bytes = 0

    start = time.time()

    print("\nKILLCHAIN AI - LOG GENERATOR")
    print("=" * 50)
    print(f"Target size: {size_gb} GB")
    print(f"Alert ratio: {alert_ratio * 100:.1f}%")
    print(f"Output: {output}")
    print("=" * 50)

    # Write in streaming mode to conserve RAM.
    with open(output, "wb", buffering=1024 * 1024) as file:

        while written_bytes < target_size:

            if random.random() < alert_ratio:
                event = generate_malicious()
                malicious_events += 1
            else:
                event = generate_benign()

            line = (
                json.dumps(event, separators=(",", ":")) + "\n"
            ).encode("utf-8")

            file.write(line)

            written_bytes += len(line)
            total_events += 1

            if total_events % 10000 == 0:

                progress = min(
                    written_bytes / target_size * 100,
                    100
                )

                print(
                    f"\rProgress: {progress:.2f}% | "
                    f"Events: {total_events:,} | "
                    f"Size: {written_bytes / 1e9:.3f} GB",
                    end="",
                    flush=True
                )

        file.flush()
        os.fsync(file.fileno())

    elapsed = time.time() - start

    print("\n\nGENERATION COMPLETE")
    print("=" * 50)
    print(f"File: {output}")
    print(f"Size: {os.path.getsize(output):,} bytes")
    print(f"Total events: {total_events:,}")
    print(f"Alert events: {malicious_events:,}")
    print(
        f"Alert percentage: "
        f"{malicious_events / total_events * 100:.2f}%"
    )
    print(f"Time taken: {elapsed:.2f} seconds")


if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument("--size", type=float, default=1)
    parser.add_argument("--alerts", type=float, default=0.20)
    parser.add_argument(
        "--output",
        default="killchain_security_logs.jsonl"
    )

    args = parser.parse_args()

    if args.size <= 0:
        parser.error("--size must be greater than zero")

    if not 0 <= args.alerts <= 1:
        parser.error("--alerts must be between 0 and 1")

    generate_dataset(
        args.size,
        args.alerts,
        args.output
    )
