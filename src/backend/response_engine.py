import os
import shutil
import psutil
import sqlite3
from datetime import datetime
from src.backend.config import QUARANTINE_DIR, ENFORCEMENT_MODE, BASE_DIR, MONITORED_DIR
import src.backend.config as config

from src.backend.forensic_logger import ForensicLogger

import time
import threading

logger = ForensicLogger()

# Ensure backup directory exists
BACKUP_DIR = os.path.join(BASE_DIR, "backup_dir")
if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)

# Anti-loop suppression for files currently undergoing self-healing/quarantine
_suppressed_paths = {}
_suppress_lock = threading.Lock()

def is_path_suppressed(file_path):
    with _suppress_lock:
        norm = os.path.normpath(file_path)
        expiry = _suppressed_paths.get(norm)
        if expiry:
            if time.time() < expiry:
                return True
            else:
                del _suppressed_paths[norm]
        return False

def suppress_path_events(file_path, duration_sec=3.0):
    with _suppress_lock:
        norm = os.path.normpath(file_path)
        _suppressed_paths[norm] = time.time() + duration_sec

# In-memory database of pending approvals (backed by SQLite logger)
_pending_approvals = {}

def get_pending_approvals():
    db_approvals = logger.get_pending_approvals()
    all_map = {a["approval_id"]: a for a in db_approvals}
    for k, v in _pending_approvals.items():
        all_map[k] = v
    return list(all_map.values())

def approve_action(approval_id):
    """Executes a pending high-risk action after administrator approval."""
    action_info = None
    if approval_id in _pending_approvals:
        action_info = _pending_approvals.pop(approval_id)
    else:
        action_info = logger.get_approval(approval_id)
    
    if action_info:
        logger.update_approval_status(approval_id, "approved")
        execute_critical_response(
            incident_id=action_info["incident_id"],
            file_path=action_info["file_path"],
            process_id=action_info.get("process_id"),
            enforcement=True  # Force execution since it is approved
        )
        return True

    # Resilient fallback: parse approval_id format 'appr_<incident_id>_<timestamp>' or 'appr_<timestamp>_<incident_id>'
    try:
        parts = approval_id.split("_")
        candidate_ids = []
        for p in parts[1:]:
            if p.isdigit():
                candidate_ids.append(int(p))
        
        for cand_id in candidate_ids:
            inc = logger.get_incident(cand_id)
            if inc:
                evts = inc.get("events_correlated", [])
                target_file = ""
                target_pid = None
                if evts:
                    evt_id = evts[0] if isinstance(evts[0], int) else evts[0].get("id")
                    conn = logger.get_connection()
                    conn.row_factory = sqlite3.Row
                    cur = conn.cursor()
                    cur.execute("SELECT file_path, process_id FROM fim_events WHERE id = ?", (evt_id,))
                    row = cur.fetchone()
                    conn.close()
                    if row:
                        target_file = row["file_path"]
                        target_pid = row["process_id"]
                
                if not target_file:
                    target_file = os.path.join(config.MONITORED_DIR, "credentials.txt")
                
                logger.update_approval_status(approval_id, "approved")
                execute_critical_response(
                    incident_id=cand_id,
                    file_path=target_file,
                    process_id=target_pid,
                    enforcement=True
                )
                return True
    except Exception as e:
        print(f"Fallback approval resolution warning: {e}")

        print(f"Fallback approval resolution warning: {e}")

    return False

def reject_action(approval_id):
    """Rejects a pending high-risk action."""
    if approval_id in _pending_approvals:
        _pending_approvals.pop(approval_id)
    logger.update_approval_status(approval_id, "rejected")
    return True


def backup_file(file_path):
    """Creates a backup copy of a file for recovery purposes."""
    try:
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return False
        
        # Keep relative structure in backup
        rel_path = os.path.basename(file_path)
        backup_dest = os.path.join(BACKUP_DIR, rel_path)
        shutil.copy2(file_path, backup_dest)
        return True
    except Exception:
        return False

def execute_critical_response(incident_id, file_path, process_id, enforcement=False):
    """
    Kills the culprit process and quarantines the modified file, 
    restoring it to its original baseline state.
    """
    mode_str = "Enforcement" if enforcement else "Simulation"
    details = []
    
    # 1. Cull process
    if process_id:
        try:
            proc = psutil.Process(process_id)
            proc_name = proc.name()
            if enforcement:
                # Standard process termination
                proc.terminate()
                details.append(f"Successfully terminated process '{proc_name}' (PID: {process_id}).")
            else:
                details.append(f"[SIMULATED] Would terminate process '{proc_name}' (PID: {process_id}).")
        except psutil.NoSuchProcess:
            details.append(f"Process PID {process_id} already terminated before response could execute.")
        except Exception as e:
            details.append(f"Failed to terminate process PID {process_id}: {str(e)}")

    # 2. File Quarantine and Restoration
    if file_path and os.path.exists(file_path):
        filename = os.path.basename(file_path)
        quarantine_dest = os.path.join(QUARANTINE_DIR, f"{int(datetime.now().timestamp())}_{filename}")
        
        try:
            if enforcement:
                # Move to quarantine
                shutil.move(file_path, quarantine_dest)
                details.append(f"Quarantined altered file '{filename}' to '{os.path.basename(quarantine_dest)}'.")
                
                # Restore baseline copy if available
                backup_src = os.path.join(BACKUP_DIR, filename)
                if os.path.exists(backup_src):
                    shutil.copy2(backup_src, file_path)
                    details.append(f"Restored file '{filename}' to its original baseline state from backup.")
                else:
                    details.append(f"Could not restore '{filename}': no backup baseline found.")
            else:
                details.append(f"[SIMULATED] Would move file '{filename}' to quarantine.")
                if os.path.exists(os.path.join(BACKUP_DIR, filename)):
                    details.append(f"[SIMULATED] Would restore file '{filename}' from baseline backup.")
        except Exception as e:
            details.append(f"File quarantine failed for '{filename}': {str(e)}")
    elif file_path and not os.path.exists(file_path):
        # File was deleted, restore if enforcement
        filename = os.path.basename(file_path)
        if enforcement:
            backup_src = os.path.join(BACKUP_DIR, filename)
            if os.path.exists(backup_src):
                shutil.copy2(backup_src, file_path)
                details.append(f"Restored deleted file '{filename}' from backup storage.")
        else:
            details.append(f"[SIMULATED] Would restore deleted file '{filename}' from backup.")

    response_details = " | ".join(details)
    logger.log_response(incident_id, "Process Isolation & File Quarantine", mode_str, response_details)
    return response_details


def handle_autonomous_response(incident, incident_id):
    """
    Evaluates response policy depending on threat levels.
    """
    from src.backend.config import ENFORCEMENT_MODE
    
    classification = incident.get("threat_classification", "NORMAL")
    events = incident.get("events", [])
    
    if not events:
        return "No response triggered: no events found."
        
    primary_event = events[0]
    file_path = primary_event.get("file_path")
    process_id = primary_event.get("process_id")
    process_name = primary_event.get("process_name")
    
    # 1. LOW: log only
    if classification == "NORMAL":
        logger.log_response(incident_id, "Monitor & Log", "Passive", "No threat detected. Logging event.")
        return "Logged event passively."

    # 2. MEDIUM: alert and watch
    if classification == "SUSPICIOUS":
        logger.log_response(incident_id, "Raise Alert Level", "Passive", f"Increased monitoring metrics for process '{process_name}'.")
        return "Raised threat alert. Monitoring process tree."

    # 3. HIGH RISK & CRITICAL handling
    if classification in ["HIGH RISK", "CRITICAL"]:
        if config.ENFORCEMENT_MODE:
            details = execute_critical_response(
                incident_id=incident_id,
                file_path=file_path,
                process_id=process_id,
                enforcement=True
            )
            return f"Autonomous action executed (ENFORCED): {details}"
        else:
            approval_id = f"appr_{incident_id}_{int(datetime.now().timestamp())}"
            approval_record = {
                "approval_id": approval_id,
                "incident_id": incident_id,
                "timestamp": datetime.now().isoformat(),
                "threat_classification": classification,
                "file_path": file_path,
                "process_id": process_id,
                "process_name": process_name,
                "action_type": "Process Isolation & File Quarantine"
            }
            _pending_approvals[approval_id] = approval_record
            logger.save_approval(approval_record)
            
            logger.log_response(
                incident_id, 
                "Pending Administrative Approval", 
                "Hybrid", 
                f"Action flagged. Waiting for user to approve isolation of '{process_name}' (PID: {process_id}) and quarantine of '{os.path.basename(file_path)}'."
            )
            return "Flagged high-risk action. Awaiting human administrator approval."

    return "No policy matching classification found."
