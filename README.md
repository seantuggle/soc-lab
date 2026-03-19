# 🔍 SOC Lab

A **local, containerized Security Operations Center (SOC) learning environment** built in Python.
This project simulates both **defensive SOC workflows** and **controlled adversary activity** to demonstrate how logs are ingested, normalized, detected, mapped to MITRE ATT&CK, and triaged by analysts — without relying on commercial SIEM platforms.

```
Log Sources → Ingest → Normalize → Detect → Alert → Triage
                ↑
           Attacker UI
```

Built to teach **how SOC systems actually work under the hood**, not just how to click dashboards.

---

## 🎯 Why This Project Exists

Most SOC labs focus on configuring tools.
This project focuses on **understanding the pipeline**.

The goal of this lab is to demonstrate:
- How raw log data becomes actionable alerts
- How rule‑based detections are designed, validated, and tuned
- How alerts map to **MITRE ATT&CK** techniques
- How analysts triage, suppress, snooze, and export alerts during investigations
- How controlled adversary activity is used to test detections

Everything runs locally and is intentionally transparent so each stage of the SOC workflow can be inspected, modified, and extended.

---

## ✅ Key Features

- Log ingestion service (FastAPI)
- Event normalization into a consistent schema
- YAML‑based detection rules (hot‑reloadable)
- MITRE ATT&CK mapping at the detection level
- Alert deduplication, suppression, and snoozing
- Dark‑themed analyst triage dashboard
- CSV and JSON alert export for reporting and investigations
- **Web‑based Attacker UI for adversary simulation**
- Scenario‑driven attack generation with realistic background noise
- Unit tests for normalization and detection logic
- Fully containerized with Docker Compose

---

## 🧠 What This Project Demonstrates

This lab was designed to showcase skills relevant to SOC Analyst, Detection Engineer, and Security Engineer roles:

- SOC architecture and end‑to‑end data flow
- Detection engineering fundamentals
- MITRE ATT&CK usage in real alerting workflows
- Log normalization and schema design
- Alert lifecycle concepts (triage, suppression, export)
- Understanding attacker behavior through controlled adversary simulation
- Python backend development with FastAPI
- Dockerized local development environments
- Writing maintainable, testable security tooling

---

## 🚀 Quick Start (Docker — Recommended)

### Requirements
- Docker Desktop (Windows / macOS) or Docker Engine (Linux)

### Run the lab
```bash
# 1. Clone the repository
git clone https://github.com/seantuggle/soc-lab.git
cd soc-lab

# 2. Start all services
docker compose up --build
```

### Open the interfaces
- **SOC Dashboard:** http://localhost:8080
- **Attacker UI:** http://localhost:8080/attacker

### Generate attack traffic (CLI alternative)
```bash
docker compose run --rm simulator python generate_events.py --scenario brute_force
```

The environment continuously generates a mix of benign and malicious activity to mimic real SOC alert noise.

---

## 🧨 Attacker UI (Adversary Simulation)

The Attacker UI provides a controlled interface for simulating adversary behavior
against the SOC pipeline.

Rather than relying on static log replays, the UI allows users to intentionally
generate attack scenarios that produce realistic telemetry, enabling:

- Detection validation and tuning
- MITRE ATT&CK coverage testing
- Analyst training and triage practice
- Signal‑to‑noise evaluation

The Attacker UI is **not a red‑team tool** and does not perform real exploitation.
It is an **adversary emulation layer** designed to safely generate events that mimic
common attacker techniques.

### Supported Scenarios
- Brute force authentication attempts
- Credential misuse and suspicious login behavior
- Suspicious process execution
- Unauthorized account creation
- DNS tunneling patterns
- Impossible travel scenarios
- Web scanning activity

Each scenario maps directly to one or more MITRE ATT&CK techniques and flows through
the same ingestion, normalization, detection, and alerting pipeline as real events.

---

## 🖥️ Quick Start (Local Python — No Docker)

### Requirements
- Python 3.10+

### Setup
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Run
```bash
chmod +x run_local.sh
./run_local.sh
```

Then open:
- http://localhost:8080

---

## 🧪 Attack Scenarios (CLI)

| Scenario | What it Simulates |
|---------|------------------|
| brute_force | Repeated SSH failures from one IP |
| cred_stuff | Failed logins followed by success |
| powershell | Suspicious command execution |
| new_user | Backdoor account creation |
| dns_tunnel | High‑frequency DNS with suspicious TLDs |
| impossible_travel | Logins from distant locations |
| web_scan | 401/404 scanning activity |
| normal | Benign baseline activity |
| all | Cycles through every scenario |

Example:
```bash
python tools/generate_events.py --scenario all --loop --interval 5
```

---

## 🧩 Project Layout

```
soc-lab/
├── services/
│   ├── ingestion/      # FastAPI log ingestion service
│   ├── detection/      # Rule evaluation engine
│   └── dashboard/      # Analyst triage UI
├── shared/             # Schemas and normalization logic
├── rules/              # YAML detection rules
├── tools/              # Attack/event simulator
├── tests/              # Unit tests for normalizers & detections
├── db/                 # SQLite database
├── docker-compose.yml
├── run_local.sh
├── README.md
├── DESIGN.md           # Architecture and design decisions
└── LAB_GUIDE.md        # Exercises and learning objectives
```

---

## 🧭 MITRE ATT&CK Integration

Detections are mapped directly to **MITRE ATT&CK techniques** at the rule level.
This allows alerts to carry technique context into the triage workflow, helping analysts:

- Classify activity
- Group related alerts
- Understand detection coverage and gaps
- Communicate findings using a shared framework

MITRE mapping is treated as **analyst context**, not decorative metadata.

---

## 📤 Alert Export

Alerts can be exported in:
- CSV (for reports and spreadsheets)
- JSON (for integrations or incident artifacts)

Exports include normalized event data, detection metadata, severity, and MITRE context.

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

Tests cover:
- Event normalization logic
- Detection rule behavior

---

## 🧠 Design Philosophy

This project prioritizes:
- Transparency over abstraction
- Realistic SOC workflows over feature bloat
- Learning and experimentation over production hardening

For deeper design decisions, see:
- DESIGN.md

---

## 📘 Learning Guide

Hands‑on exercises and guided exploration are available in:
- LAB_GUIDE.md

---

## 🚧 Disclaimer

This project is for **educational and learning purposes only**.
It is not intended for production use.
