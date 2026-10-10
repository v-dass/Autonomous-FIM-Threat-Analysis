import os
from src.backend.config import WEIGHTS, SENSITIVE_FILES

# Known suspicious processes in normal file update context
SUSPICIOUS_PROCESS_NAMES = [
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", 
    "nc.exe", "netcat.exe", "curl.exe", "bash.exe", "schtasks.exe",
    "malware.exe", "malware"
]

def map_mitre_attack(event_type, file_path, process_name, trust_score, anomaly_score):
    """
    Maps events to MITRE ATT&CK techniques based on behavior, process context, and ML anomaly indicators.
    """
    file_name = os.path.basename(file_path).lower()
    proc_name = process_name.lower()
    
    # Check for defense evasion (Tampering with FIM or system config files)
    if "src" in file_path or file_name.endswith(".py") or file_name == "config.py":
        return {
            "technique_id": "T1562.001",
            "technique_name": "Impair Defenses: Disable or Modify Tools",
            "tactic": "Defense Evasion",
            "evidence": f"Modification of security agent source file '{file_name}' by '{process_name}'",
            "confidence": "High"
        }
        
    # Check for indicator removal (Tampering with log database)
    if file_name == "forensics.db":
        return {
            "technique_id": "T1564.001",
            "technique_name": "Indicator Removal on Host",
            "tactic": "Defense Evasion",
            "evidence": "Direct modification of forensics logging database file.",
            "confidence": "High"
        }

    # Data destruction (File deletions)
    if event_type == "DELETED":
        return {
            "technique_id": "T1485",
            "technique_name": "Data Destruction",
            "tactic": "Impact",
            "evidence": f"Monitored asset '{file_name}' was deleted.",
            "confidence": "High"
        }

    # Data Alteration (Modification of monitored files)
    if event_type == "MODIFIED":
        return {
            "technique_id": "T1565.001",
            "technique_name": "Data Alteration: Stored Data Manipulation",
            "tactic": "Impact",
            "evidence": f"Monitored asset '{file_name}' was modified by process '{process_name}'.",
            "confidence": "High"
        }

    # Execution via shell scripting
    if proc_name in ["powershell.exe", "cmd.exe"]:
        if anomaly_score > 0.5:
            return {
                "technique_id": "T1059.001",
                "technique_name": "Command and Scripting Interpreter: PowerShell",
                "tactic": "Execution",
                "evidence": f"PowerShell/Command shell executed modifications in target directory.",
                "confidence": "Medium"
            }

    # User execution
    if proc_name in ["explorer.exe"] and event_type == "CREATED" and file_name.endswith((".exe", ".bat", ".ps1")):
        return {
            "technique_id": "T1204.002",
            "technique_name": "User Execution: Malicious File",
            "tactic": "Execution",
            "evidence": f"Executable/script file '{file_name}' created under monitored directory.",
            "confidence": "Medium"
        }

    return None


def calculate_risk_score(event_data, anomaly_metrics, trust_metrics):
    """
    Synthesizes SHA-256 integrity, ML anomaly scores, process context, and runtime trust
    to calculate a final dynamic Risk Score (0-100) and returns classification details.
    """
    reasons = []
    
    # 1. SHA-256 Integrity Verification Signal (0 or 25 points)
    integrity_score = 0
    if event_data.get("integrity_status") == "Integrity Violated":
        integrity_score = WEIGHTS["integrity_violation"]
        reasons.append("✓ File integrity baseline violated (SHA-256 mismatch)")
    else:
        reasons.append("✓ File SHA-256 hash matches expected baseline")

    # 2. ML Anomaly Detection Signal (0 to 25 points)
    anomaly_score_val = anomaly_metrics.get("anomaly_score", 0.0)
    ml_contribution = anomaly_score_val * WEIGHTS["ml_anomaly"]
    if anomaly_score_val > 0.7:
        reasons.append(f"✓ Critical ML anomaly score: {anomaly_score_val:.2f}")
    elif anomaly_score_val > 0.4:
        reasons.append(f"✓ Moderate ML anomaly score: {anomaly_score_val:.2f}")

    # 3. Runtime Attestation Trust Score Contribution (0 to 30 points)
    trust_score = trust_metrics.get("score", 100)
    trust_degradation = 100 - trust_score
    trust_contribution = (trust_degradation / 100.0) * WEIGHTS["runtime_trust_degradation"]
    if trust_score < 70:
        reasons.append(f"✓ Runtime environment trust is COMPROMISED/DEGRADED (Score: {trust_score})")
    elif trust_score < 90:
        reasons.append(f"✓ Runtime environment trust has warnings (Score: {trust_score})")

    # 4. User and Process Context suspicion (0 to 20 points)
    proc_name = event_data.get("process_name", "").lower()
    file_path = event_data.get("file_path", "")
    file_name = os.path.basename(file_path).lower()
    
    context_score = 0
    # Process check
    is_suspicious_proc = any(p in proc_name for p in SUSPICIOUS_PROCESS_NAMES)
    if is_suspicious_proc:
        context_score += 10
        reasons.append(f"✓ Suspicious process execution source: '{event_data.get('process_name')}'")
        
    # File sensitivity check
    is_sensitive = file_name in SENSITIVE_FILES or "src" in file_path
    if is_sensitive:
        context_score += 10
        reasons.append(f"✓ Target file is highly sensitive: '{file_name}'")

    context_contribution = (context_score / 20.0) * WEIGHTS["process_context_suspicion"]

    # Final Risk Summation
    total_risk = integrity_score + ml_contribution + trust_contribution + context_contribution
    
    # Any integrity violation on an ingested asset is at least HIGH RISK (68)
    if integrity_score > 0:
        total_risk = max(total_risk, 68.0)
        reasons.append("🚨 Monitored asset integrity breached: Cryptographic SHA-256 hash mismatch detected.")

    # Priority escalation: If a known suspicious/malicious process violates the integrity
    if is_suspicious_proc and integrity_score > 0:
        total_risk = max(total_risk, 88.0)
        reasons.append("🚨 Critical escalation: Suspicious process tampering with monitored asset.")

    total_risk = round(max(0.0, min(100.0, total_risk)))

    # Threat Classification
    if total_risk < 30:
        classification = "NORMAL"
    elif total_risk < 60:
        classification = "SUSPICIOUS"
    elif total_risk < 80:
        classification = "HIGH RISK"
    else:
        classification = "CRITICAL"

    # MITRE ATT&CK Mapping
    mitre = map_mitre_attack(
        event_type=event_data.get("event_type"),
        file_path=file_path,
        process_name=event_data.get("process_name", "Unknown"),
        trust_score=trust_score,
        anomaly_score=anomaly_score_val
    )

    return {
        "risk_score": total_risk,
        "threat_classification": classification,
        "mitre_mapping": mitre,
        "reasons": reasons
    }
