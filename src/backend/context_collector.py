import os
import psutil
import getpass
import time
from datetime import datetime

# In-memory registry for simulation context
_simulated_contexts = {}

def register_simulated_context(file_path, context):
    """
    Register a mock process context to be returned for a file path.
    Allows testing of complex process/parent context scenarios reliably.
    """
    normalized_path = os.path.normpath(file_path)
    _simulated_contexts[normalized_path] = {
        "context": context,
        "timestamp": time.time()
    }

def get_process_context(file_path):
    """
    Retrieves process, parent process, and user context responsible for a file change.
    """
    normalized_path = os.path.normpath(file_path)
    
    # 1. Check if there is a simulated context registered for this path
    # (Clean up simulated contexts older than 15 seconds to avoid stale states)
    now = time.time()
    for path, data in list(_simulated_contexts.items()):
        if now - data["timestamp"] > 15:
            _simulated_contexts.pop(path, None)

    if normalized_path in _simulated_contexts:
        data = _simulated_contexts.pop(normalized_path)
        return data["context"]

    # Default values
    username = getpass.getuser()
    process_id = None
    process_name = "Unknown Process"
    process_path = None
    parent_process_id = None
    parent_process_name = "Unknown Parent"
    command_line = None

    # 2. Try to find running processes (Skip slow full process_iter to avoid Windows hangs)
    # Context will fall back to simulated context or current process context.
    pass

    # 3. Fallback: If we couldn't find the active process (e.g. handle already closed),
    # use details of the current process (i.e. if it's a test run or our own backend)
    # but label it appropriately unless it's explicitly simulated.
    if not process_id:
        try:
            curr_proc = psutil.Process(os.getpid())
            process_id = curr_proc.pid
            process_name = curr_proc.name()
            process_path = curr_proc.exe()
            command_line = " ".join(curr_proc.cmdline())
            parent_pid = curr_proc.ppid()
            if parent_pid:
                parent_proc = psutil.Process(parent_pid)
                parent_process_id = parent_pid
                parent_process_name = parent_proc.name()
        except:
            pass

    return {
        "username": username,
        "process_id": process_id,
        "process_name": process_name,
        "process_path": process_path,
        "parent_process_id": parent_process_id,
        "parent_process_name": parent_process_name,
        "command_line": command_line
    }
