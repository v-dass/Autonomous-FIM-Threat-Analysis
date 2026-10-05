import os
import hashlib
import time
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import src.backend.config as config
from src.backend.config import BACKEND_DIR, BASE_DIR
from src.backend.forensic_logger import ForensicLogger
from src.backend.context_collector import get_process_context
from src.backend.response_engine import is_path_suppressed

logger = ForensicLogger()

def calculate_sha256(file_path):
    """Calculates the SHA-256 hash of a file."""
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

def create_initial_baseline():
    """Scans the monitored directory and establishes the SHA-256 baseline."""
    logger.clear_baselines()
    if not os.path.exists(config.MONITORED_DIR):
        os.makedirs(config.MONITORED_DIR)
        
    for root, _, files in os.walk(config.MONITORED_DIR):
        for file in files:
            file_path = os.path.normpath(os.path.join(root, file))
            sha256 = calculate_sha256(file_path)
            if sha256:
                stat = os.stat(file_path)
                logger.save_baseline(
                    file_path=file_path,
                    sha256=sha256,
                    file_size=stat.st_size,
                    created_at=datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    modified_at=datetime.fromtimestamp(stat.st_mtime).isoformat()
                )

# In-memory flag to trigger attestation warnings on self-modification
_self_tampering_occurred = False
_tampered_components = set()

def get_self_tampering_status():
    global _self_tampering_occurred, _tampered_components
    return _self_tampering_occurred, list(_tampered_components)

def clear_self_tampering_status():
    global _self_tampering_occurred, _tampered_components
    _self_tampering_occurred = False
    _tampered_components.clear()

class SecurityEventHandler(FileSystemEventHandler):
    def __init__(self, on_event_callback=None):
        super().__init__()
        self.on_event_callback = on_event_callback

    def process_event(self, event, is_self_protection=False):
        if event.is_directory:
            return

        file_path = os.path.normpath(event.src_path)
        
        # Ignore suppressed files (undergoing SOAR restoration/quarantine) to avoid feedback loops
        if is_path_suppressed(file_path):
            return

        # Ignore database file modifications to avoid loops
        if "forensics.db" in file_path or file_path.endswith(".db-journal") or file_path.endswith(".db-wal"):
            return

        event_type = event.event_type.upper()
        if event_type == "MOVED":
            # For moved events, watchdog gives dest_path
            dest_path = os.path.normpath(event.dest_path)
            self.handle_single_event(file_path, "DELETED", is_self_protection)
            self.handle_single_event(dest_path, "CREATED", is_self_protection)
        else:
            self.handle_single_event(file_path, event_type, is_self_protection)

    def handle_single_event(self, file_path, event_type, is_self_protection):
        global _self_tampering_occurred, _tampered_components
        
        if is_self_protection:
            # Self-protection monitoring checks (security backend core components only)
            from src.backend.config import ATTESTATION_TARGETS
            target_paths = {os.path.normpath(p) for p in ATTESTATION_TARGETS.values()}
            norm_file = os.path.normpath(file_path)
            if norm_file in target_paths:
                _self_tampering_occurred = True
                component_name = os.path.basename(file_path).replace(".py", "")
                _tampered_components.add(component_name)
            return

        # Regular File Integrity Monitoring
        current_hash = calculate_sha256(file_path)
        baseline = logger.get_baseline(file_path)
        
        hash_before = baseline["sha256"] if baseline else None
        hash_after = current_hash
        integrity_status = "Integrity Preserved"

        if event_type == "DELETED":
            integrity_status = "Integrity Violated"
        elif event_type == "CREATED":
            if hash_before and hash_before == current_hash:
                integrity_status = "Integrity Preserved"
            else:
                integrity_status = "Integrity Violated"
        elif event_type == "MODIFIED":
            if hash_before and hash_before != hash_after:
                integrity_status = "Integrity Violated"
            elif not hash_before:
                integrity_status = "Integrity Violated"

        # Update baseline on creation or modification
        if event_type in ["CREATED", "MODIFIED"] and current_hash:
            try:
                stat = os.stat(file_path)
                logger.save_baseline(
                    file_path=file_path,
                    sha256=current_hash,
                    file_size=stat.st_size,
                    created_at=datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    modified_at=datetime.fromtimestamp(stat.st_mtime).isoformat()
                )
            except Exception:
                pass

        # Capture Process and User context
        context = get_process_context(file_path)
        
        event_record = {
            "timestamp": datetime.now().isoformat(),
            "file_path": file_path,
            "event_type": event_type,
            "hash_before": hash_before,
            "hash_after": hash_after,
            "integrity_status": integrity_status,
            "username": context["username"],
            "process_id": context["process_id"],
            "process_name": context["process_name"],
            "process_path": context["process_path"],
            "parent_process_id": context["parent_process_id"],
            "parent_process_name": context["parent_process_name"],
            "command_line": context["command_line"]
        }

        # Log event in forensic database
        event_id = logger.log_fim_event(event_record)
        event_record["id"] = event_id

        # Notify downstream threat analysis pipeline
        if self.on_event_callback:
            self.on_event_callback(event_record)

    def on_created(self, event):
        self.process_event(event)

    def on_modified(self, event):
        # We watch both MONITORED_DIR and src
        # Identify based on path which watch triggered it
        path = os.path.normpath(event.src_path)
        is_self = "src" in path or BACKEND_DIR in path
        self.process_event(event, is_self_protection=is_self)

    def on_deleted(self, event):
        path = os.path.normpath(event.src_path)
        is_self = "src" in path or BACKEND_DIR in path
        self.process_event(event, is_self_protection=is_self)

    def on_moved(self, event):
        path = os.path.normpath(event.src_path)
        is_self = "src" in path or BACKEND_DIR in path
        self.process_event(event, is_self_protection=is_self)


class FileIntegrityMonitor:
    def __init__(self, on_event_callback=None):
        self.observer = None
        self.on_event_callback = on_event_callback
        self.handler = SecurityEventHandler(on_event_callback)

    def start(self):
        create_initial_baseline()
        self.observer = Observer()
        
        # 1. Monitored Directory Watch
        if os.path.exists(config.MONITORED_DIR):
            self.observer.schedule(self.handler, config.MONITORED_DIR, recursive=True)
            
        # 2. Self-Protection Directory Watch (watching the src folder)
        src_dir = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
        if os.path.exists(src_dir):
            self.observer.schedule(self.handler, src_dir, recursive=True)
            
        self.observer.start()

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
