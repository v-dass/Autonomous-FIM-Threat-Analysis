# AETHER-FIM: Autonomous AI-Powered File Integrity Monitoring & Threat Mitigation System

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Cybersecurity SOAR](https://img.shields.io/badge/Cybersecurity-Autonomous%20SOAR-red.svg)](#)

---

## 🛡️ Project Overview
**AETHER-FIM** (Autonomous Enterprise Threat Hunting, Evaluation & Remediation FIM) is a next-generation File Integrity Monitoring (FIM) and incident response platform. Unlike legacy signature-based or passive hash-polling systems, AETHER-FIM combines:
- **Zero-Latency Kernel Telemetry:** Real-time OS event hooking via Windows ReadDirectoryChangesW/Watchdog with deep process attribution (PID, parent PID, executable path, binary hash, cryptographic signature, and security token elevation).
- **Runtime Cryptographic Attestation:** TPM-inspired continuous baseline verification calculating self-integrity trust scores to prevent tampering with security binaries.
- **Unsupervised ML Behavioral Anomaly Detection:** Real-time Isolation Forest evaluating multi-dimensional entropy, burst event frequencies, after-hours file touches, and user SID anomalies.
- **Dynamic Multi-Stage Threat Correlation & Risk Engine:** Multi-factor threat matrix escalating scores based on MITRE ATT&CK tactics, ransomware file header patterns, and process parentage.
- **Explainable AI Reasoning (LLM Copilot):** Generates structured cyber threat intelligence, root-cause deductions, and defensible tactical recommendations.
- **Autonomous Closed-Loop SOAR:** Instant process quarantine/termination, automatic file self-restoration from secure shadow baselines, and path event suppression to eliminate remediation feedback loops.
- **Modern Executive SOC HUD:** High-density real-time monitoring interface with custom file/folder ingestion, interactive approval gates, visual risk radar, and tamper-evident SQLite WAL forensic ledger.

---

## 👥 Team Work Breakdown Structure

| Member | Focus Area | Key Modules |
| :--- | :--- | :--- |
| **Member 1 (Lead)** | **Core FIM & Kernel Telemetry** | config.py, context_collector.py, im_service.py |
| **Member 2** | **Runtime Attestation & Machine Learning** | ttestation_engine.py, ml_engine.py |
| **Member 3** | **Threat Correlation, Risk Engine & LLM Copilot** | correlation_engine.py, 
isk_engine.py, llm_reasoning.py |
| **Member 4** | **Autonomous SOAR, Forensic Ledger & SOC HUD** | 
esponse_engine.py, orensic_logger.py, main.py, rontend/ |

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.10, 3.11, or 3.12
- Windows 10/11 or Windows Server

### 1. Installation
Clone the repository:
`ash
git clone https://github.com/v-dass/Autonomous-FIM-Threat-Analysis.git
cd Autonomous-FIM-Threat-Analysis
`

Create and activate a virtual environment:
`ash
python -m venv venv
.\venv\Scripts\activate
`

Install dependencies:
`ash
pip install -r requirements.txt
`

### 2. Launching the System
`ash
# Option A: One-click batch runner
run_project.bat

# Option B: Manual uvicorn command
python -m uvicorn src.backend.main:app --host 127.0.0.1 --port 8000 --reload
`

Open your browser at:
`
http://127.0.0.1:8000
`
