import os
import json
import requests
from datetime import datetime
from src.backend.config import SENSITIVE_FILES

# RAG Knowledge base (Simple local repository of security techniques & mitigations)
RAG_SECURITY_KNOWLEDGE = {
    "T1562.001": {
        "technique": "T1562.001 - Impair Defenses: Disable or Modify Tools",
        "description": "Adversaries may modify or disable security tools to avoid detection. This includes tampering with agents, logs, configuration files, or database files.",
        "mitigation": "Configure strict directory permissions, restrict write access to administrators only, enable tamper-protection features, and isolate alerts immediately when file integrity checks on security binaries fail."
    },
    "T1485": {
        "technique": "T1485 - Data Destruction",
        "description": "Adversaries may destroy data to disrupt operations or cover their tracks. Deletion of logs or critical credentials is often associated with ransomware or host cleanup.",
        "mitigation": "Enable remote syslog forwarding, configure shadow copy backups, and enforce strict process execution limits on administrative shells."
    },
    "T1565.001": {
        "technique": "T1565.001 - Data Alteration: Stored Data Manipulation",
        "description": "Adversaries may insert or modify stored data on a system to disrupt transactions, insert backdoors, or alter configuration files.",
        "mitigation": "Establish a rigid file integrity baseline, enforce application whitelisting, and alert on non-standard processes modifying configuration files."
    },
    "T1059.001": {
        "technique": "T1059.001 - Command and Scripting Interpreter: PowerShell",
        "description": "Adversaries may use PowerShell commands to download files, execute payloads, or interact with system components directly in memory.",
        "mitigation": "Enable PowerShell Constrained Language Mode, enforce script signing policies, and monitor parent-child process relationships."
    },
    "T1204.002": {
        "technique": "T1204.002 - User Execution: Malicious File",
        "description": "An user may execute a malicious file (like a batch script or executable) that drops tools or schedules persistence tasks.",
        "mitigation": "Train users on file-opening safety, block downloads from untrusted sources, and enforce execution blocks on temporary/download folders."
    }
}

def generate_local_reasoning(incident):
    """
    Advanced offline template reasoning representing an expert SOC security analyst.
    Grounds all analysis in actual incident facts and local RAG information.
    """
    events = incident.get("events", [])
    if not events:
        return {
            "summary": "Insufficient evidence for confident threat determination.",
            "reasoning": "No file integrity events are available in this incident group.",
            "action": "Maintain continuous system monitoring."
        }

    # Group variables
    risk_score = incident.get("risk_score", 0)
    classification = incident.get("threat_classification", "NORMAL")
    mitre_map = incident.get("mitre_mapping")
    
    # Analyze primary event
    primary_event = events[0]
    file_path = primary_event.get("file_path", "")
    filename = os.path.basename(file_path)
    proc_name = primary_event.get("process_name", "Unknown")
    pid = primary_event.get("process_id")
    user = primary_event.get("username", "Unknown")
    event_type = primary_event.get("event_type", "MODIFIED")
    
    # If the activity is low risk and normal
    if classification == "NORMAL":
        return {
            "summary": "Insufficient evidence for confident threat determination.",
            "reasoning": (
                f"The modification of file '{filename}' was performed by process '{proc_name}' (PID: {pid}) "
                f"under user '{user}'. The overall risk score of {risk_score} falls within normal boundaries. "
                "No anomalous patterns or runtime attestation violations were flagged during this window."
            ),
            "action": "Log incident. Continue standard runtime monitoring."
        }

    # Build report based on risk
    mitre_tech = "No confident MITRE ATT&CK mapping."
    mitre_details = ""
    
    if mitre_map:
        tech_id = mitre_map.get("technique_id")
        mitre_tech = f"{mitre_map.get('technique_name')} ({tech_id})"
        rag_info = RAG_SECURITY_KNOWLEDGE.get(tech_id, {})
        mitre_details = f"\n**MITRE ATT&CK Technique Context:**\n{rag_info.get('description', '')}"

    summary = f"Detecting {classification} Activity on File Integrity Monitor"
    
    # Structure of details
    reasoning_md = (
        f"#### Security Analysis Report\n"
        f"- **Primary Target:** `{filename}` (Path: `{file_path}`)\n"
        f"- **Trigger Process:** `{proc_name}` (PID: `{pid}`) spawned by parent `{primary_event.get('parent_process_name')} (PID: {primary_event.get('parent_process_id')})`\n"
        f"- **User Context:** `{user}`\n"
        f"- **Risk Score:** `{risk_score}/100` ({classification})\n\n"
        f"#### Deductive Analysis & RAG Alignment\n"
        f"The file integrity system observed a `{event_type}` event. "
        f"The integrity check reported state: `{primary_event.get('integrity_status')}`. "
    )
    
    if "src" in file_path or filename.endswith(".py"):
        reasoning_md += (
            "The event targets the security prototype's own directory structure. "
            "Tampering with security service code is a critical indicator of Defense Evasion, "
            "designed to disable monitors prior to executing further payload components. "
        )
    elif filename in SENSITIVE_FILES:
        reasoning_md += (
            f"The target file '{filename}' is registered as highly sensitive. "
            f"Modifying critical storage components outside typical deployment windows represents an anomaly. "
        )
        
    if proc_name.lower() in ["cmd.exe", "powershell.exe"]:
        reasoning_md += (
            "The change was launched from an interactive/scripting shell. "
            "System shells should rarely interact directly with protected files unless during active administration. "
        )

    # Incorporate Attestation status
    if risk_score > 70:
        reasoning_md += (
            "\nFurthermore, Runtime Attestation checks indicated a degradation in trust. "
            "This suggests the modification was either executed to subvert FIM code or "
            "occurred while the running security environment was partially compromised."
        )

    reasoning_md += f"\n{mitre_details}"

    # Recommended Actions
    actions_md = f"1. Audit the process tree of PID {pid} to verify parent shell spawning.\n"
    if classification == "CRITICAL":
        actions_md += (
            f"2. **ISOLATE PROCESS** immediately to restrict file system hooks.\n"
            f"3. **RESTORE FILE** `{filename}` to its baseline SHA-256 state from forensic storage.\n"
            f"4. Quarantine any unidentified binary executable from monitored zones."
        )
    elif classification == "HIGH RISK":
        actions_md += (
            f"2. Flag process `{proc_name}` and require human administrative confirmation.\n"
            f"3. Increase Watchdog polling frequency on sensitive directories.\n"
            f"4. Roll passwords/credentials if target contains authentication tokens."
        )
    else:
        actions_md += "2. Continue passive monitoring and verify process identity."

    return {
        "summary": summary,
        "reasoning": reasoning_md,
        "action": actions_md
    }

def analyze_threat_llm(incident):
    """
    Threat analyst entry point. Connects to Gemini API if available, 
    otherwise falls back to rule-based RAG reasoning.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return generate_local_reasoning(incident)

    # Prepare system prompt and variables
    try:
        # Construct RAG context
        rag_context = json.dumps(RAG_SECURITY_KNOWLEDGE, indent=2)
        
        prompt = {
            "contents": [{
                "parts": [{
                    "text": (
                        f"You are a Senior Threat Analyst AI. Analyze this cybersecurity incident.\n\n"
                        f"### Incident Details:\n{json.dumps(incident, indent=2)}\n\n"
                        f"### RAG Security Knowledge Base:\n{rag_context}\n\n"
                        f"Provide a structured analysis. You must ground your analysis strictly in the provided "
                        f"evidence. If there is insufficient evidence to determine a threat, start your "
                        f"Threat Summary or report with the exact phrase: 'Insufficient evidence for confident threat determination.'\n\n"
                        f"Output your analysis in JSON format with three keys: 'summary', 'reasoning', 'action'."
                    )
                }]
            }],
            "generationConfig": {
                "responseMimeType": "application/json"
            }
        }

        # Call Gemini 1.5 Flash (standard model for fast reasoning)
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        response = requests.post(url, json=prompt, headers={"Content-Type": "application/json"}, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            content = result["candidates"][0]["content"]["parts"][0]["text"]
            return json.loads(content)
        else:
            return generate_local_reasoning(incident)
            
    except Exception as e:
        # Fall back to local rules on error
        return generate_local_reasoning(incident)
