import os
import time
import threading
from datetime import datetime
from src.backend.config import ATTESTATION_TARGETS, PENALTIES, DB_PATH
from src.backend.forensic_logger import ForensicLogger

# We import the hash calculator from fim_service but avoid circular import issues
logger = ForensicLogger()

# Thread-safe storage for latest attestation status
_attestation_lock = threading.Lock()
_current_trust_score = 100
_current_trust_state = "TRUSTED"
_active_violations = {}
_attestation_baseline_hashes = {}
_fim_running = True  # Tracks FIM observer state
_simulated_violations = {}

def calculate_sha256_simple(file_path):
    import hashlib
    if not os.path.exists(file_path) or os.path.isdir(file_path):
        return None
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def establish_attestation_baseline():
    """Establishes the trusted baseline for attestation targets."""
    global _attestation_baseline_hashes
    with _attestation_lock:
        for name, path in ATTESTATION_TARGETS.items():
            h = calculate_sha256_simple(path)
            if h:
                _attestation_baseline_hashes[name] = h

def set_fim_status(running: bool):
    """Updates whether the FIM background service is healthy/running."""
    global _fim_running
    _fim_running = running

def trigger_simulated_attestation_violation(violation_type: str, penalty_points: int, details: str):
    """Simulates a runtime violation for test purposes."""
    global _simulated_violations
    _simulated_violations[violation_type] = {
        "points": penalty_points,
        "details": details
    }

def clear_simulated_attestation_violations():
    global _simulated_violations
    _simulated_violations.clear()

def perform_attestation_check():
    """
    Performs verification of security components against the baseline.
    Calculates the Runtime Trust Score.
    """
    global _current_trust_score, _current_trust_state, _active_violations
    
    violations = {}
    score = 100

    # 1. Check FIM process status
    if not _fim_running:
        violations["fim_process_stopped"] = {
            "component": "fim_service",
            "message": "File Integrity Monitoring process is not running.",
            "penalty": PENALTIES["fim_process_stopped"]
        }
        score -= PENALTIES["fim_process_stopped"]

    # 2. Check FIM self-protection code alterations
    # Check if files have changed against our in-memory baseline
    from src.backend.fim_service import get_self_tampering_status
    self_tampered, tampered_files = get_self_tampering_status()
    if self_tampered:
        for component in tampered_files:
            penalty_key = f"{component}_tampered"
            penalty = PENALTIES.get(penalty_key, 40)
            violations[f"{component}_tampered"] = {
                "component": component,
                "message": f"Security component file '{component}.py' was modified at runtime.",
                "penalty": penalty
            }
            score -= penalty

    # Re-verify hashes of all targets directly just in case Watchdog was bypassed
    for name, path in ATTESTATION_TARGETS.items():
        current_hash = calculate_sha256_simple(path)
        expected_hash = _attestation_baseline_hashes.get(name)
        
        # If hash doesn't match and we haven't already reported it
        if current_hash and expected_hash and current_hash != expected_hash:
            violation_key = f"{name}_tampered"
            if violation_key not in violations:
                penalty = PENALTIES.get(violation_key, 40)
                violations[violation_key] = {
                    "component": name,
                    "message": f"Critical security component '{name}' has mismatched SHA-256 baseline.",
                    "penalty": penalty
                }
                score -= penalty

    # 3. Add simulated violations for test scenarios
    for v_type, v_info in _simulated_violations.items():
        if v_type not in violations:
            violations[v_type] = {
                "component": "simulation",
                "message": v_info["details"],
                "penalty": v_info["points"]
            }
            score -= v_info["points"]

    # Bound the score between 0 and 100
    score = max(0, min(100, score))
    
    # Classify state
    if score >= 90:
        state = "TRUSTED"
    elif score >= 70:
        state = "CAUTION"
    elif score >= 40:
        state = "DEGRADED"
    else:
        state = "COMPROMISED"

    # Save to memory
    with _attestation_lock:
        _current_trust_score = score
        _current_trust_state = state
        _active_violations = violations

    # Log to DB if there is a state change or active violations
    # To avoid DB spamming, we can log every time violations exist, or periodically
    logger.log_attestation(score, state, list(violations.values()))

def get_runtime_trust():
    """Returns the current trust score, state, and active violations."""
    with _attestation_lock:
        return {
            "score": _current_trust_score,
            "state": _current_trust_state,
            "violations": list(_active_violations.values())
        }

def _attestation_loop(interval_sec):
    establish_attestation_baseline()
    while True:
        try:
            perform_attestation_check()
        except Exception as e:
            # Prevent crashes in background threat
            pass
        time.sleep(interval_sec)

def start_attestation_monitoring(interval_sec=5):
    """Starts the continuous remote/runtime attestation daemon thread."""
    t = threading.Thread(target=_attestation_loop, args=(interval_sec,), daemon=True)
    t.start()
    return t
