import os

# Base paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MONITORED_DIR = os.path.join(BASE_DIR, "monitored_dir")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine_dir")
DB_PATH = os.path.join(BASE_DIR, "forensics.db")

# Self-protection / Runtime Attestation targets
BACKEND_DIR = os.path.abspath(os.path.dirname(__file__))
ATTESTATION_TARGETS = {
    "fim_service": os.path.join(BACKEND_DIR, "fim_service.py"),
    "attestation_engine": os.path.join(BACKEND_DIR, "attestation_engine.py"),
    "config": os.path.join(BACKEND_DIR, "config.py"),
    "forensic_logger": os.path.join(BACKEND_DIR, "forensic_logger.py"),
    "main": os.path.join(BACKEND_DIR, "main.py"),
    "ml_engine": os.path.join(BACKEND_DIR, "ml_engine.py"),
}

# Ensure folders exist
for folder in [MONITORED_DIR, QUARANTINE_DIR]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# Configuration settings
ENFORCEMENT_MODE = False  # Start in Simulation Mode by default

# Trust score parameters
TRUST_THRESHOLD_TRUSTED = 90
TRUST_THRESHOLD_CAUTION = 70
TRUST_THRESHOLD_DEGRADED = 40

# Attestation Penalty Scores
PENALTIES = {
    "fim_process_stopped": 50,
    "fim_service_tampered": 40,
    "attestation_engine_tampered": 40,
    "main_tampered": 40,
    "config_tampered": 30,
    "forensic_logger_tampered": 30,
    "unauthorized_privilege_escalation": 25,
}

# Threat Sensitivity: Define files in monitored directory that are critical
SENSITIVE_FILES = [
    "credentials.txt",
    "policy.json",
    "shadow",
    "passwd",
    "private.key",
    "config.json",
]

# Risk weights
WEIGHTS = {
    "integrity_violation": 25,
    "ml_anomaly": 25,
    "runtime_trust_degradation": 30,
    "process_context_suspicion": 20,
}
