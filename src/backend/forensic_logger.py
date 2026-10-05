import sqlite3
import json
import os
from datetime import datetime
from src.backend.config import DB_PATH

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. File Integrity events table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS fim_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            file_path TEXT NOT NULL,
            event_type TEXT NOT NULL,
            hash_before TEXT,
            hash_after TEXT,
            integrity_status TEXT NOT NULL,
            username TEXT,
            process_id INTEGER,
            process_name TEXT,
            process_path TEXT,
            parent_process_id INTEGER,
            parent_process_name TEXT,
            command_line TEXT
        )
    """)
    
    # 2. Attestation logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attestation_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            trust_score INTEGER NOT NULL,
            trust_state TEXT NOT NULL,
            violations TEXT
        )
    """)
    
    # 3. Security Incidents table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            threat_classification TEXT NOT NULL,
            mitre_mapping TEXT,
            llm_summary TEXT,
            llm_reasoning TEXT,
            llm_action TEXT,
            events_correlated TEXT,
            attack_graph TEXT
        )
    """)
    
    # 4. Response Actions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            incident_id INTEGER,
            action_taken TEXT NOT NULL,
            mode TEXT NOT NULL,
            details TEXT
        )
    """)
    
    # 5. File baselines (reference hashes)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_baselines (
            file_path TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            modified_at TEXT NOT NULL
        )
    """)

    # 6. Pending Administrative Approvals
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pending_approvals (
            approval_id TEXT PRIMARY KEY,
            incident_id INTEGER,
            timestamp TEXT NOT NULL,
            threat_classification TEXT,
            file_path TEXT,
            process_id INTEGER,
            process_name TEXT,
            action_type TEXT,
            status TEXT DEFAULT 'pending'
        )
    """)
    
    conn.commit()
    conn.close()


class ForensicLogger:
    def __init__(self):
        init_db()

    def get_connection(self):
        return sqlite3.connect(DB_PATH)

    def save_baseline(self, file_path, sha256, file_size, created_at, modified_at):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO file_baselines (file_path, sha256, file_size, created_at, modified_at)
            VALUES (?, ?, ?, ?, ?)
        """, (file_path, sha256, file_size, created_at, modified_at))
        conn.commit()
        conn.close()

    def get_baseline(self, file_path):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT sha256, file_size FROM file_baselines WHERE file_path = ?", (file_path,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return {"sha256": row[0], "file_size": row[1]}
        return None

    def get_all_baselines(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT file_path, sha256, file_size, created_at, modified_at FROM file_baselines")
        rows = cursor.fetchall()
        conn.close()
        return [
            {
                "file_path": row[0],
                "sha256": row[1],
                "file_size": row[2],
                "created_at": row[3],
                "modified_at": row[4]
            }
            for row in rows
        ]

    def clear_baselines(self):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM file_baselines")
        conn.commit()
        conn.close()

    def log_fim_event(self, event_data):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO fim_events (
                timestamp, file_path, event_type, hash_before, hash_after, 
                integrity_status, username, process_id, process_name, 
                process_path, parent_process_id, parent_process_name, command_line
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_data.get("timestamp", datetime.now().isoformat()),
            event_data.get("file_path"),
            event_data.get("event_type"),
            event_data.get("hash_before"),
            event_data.get("hash_after"),
            event_data.get("integrity_status"),
            event_data.get("username"),
            event_data.get("process_id"),
            event_data.get("process_name"),
            event_data.get("process_path"),
            event_data.get("parent_process_id"),
            event_data.get("parent_process_name"),
            event_data.get("command_line")
        ))
        event_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return event_id

    def log_attestation(self, score, state, violations):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO attestation_logs (timestamp, trust_score, trust_state, violations)
            VALUES (?, ?, ?, ?)
        """, (datetime.now().isoformat(), score, state, json.dumps(violations)))
        log_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return log_id

    def log_incident(self, incident_data):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO incidents (
                timestamp, risk_score, threat_classification, mitre_mapping,
                llm_summary, llm_reasoning, llm_action, events_correlated, attack_graph
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident_data.get("timestamp", datetime.now().isoformat()),
            incident_data.get("risk_score"),
            incident_data.get("threat_classification"),
            json.dumps(incident_data.get("mitre_mapping")),
            incident_data.get("llm_summary"),
            incident_data.get("llm_reasoning"),
            incident_data.get("llm_action"),
            json.dumps(incident_data.get("events_correlated")),
            json.dumps(incident_data.get("attack_graph"))
        ))
        incident_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return incident_id

    def log_response(self, incident_id, action_taken, mode, details):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO responses (timestamp, incident_id, action_taken, mode, details)
            VALUES (?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), incident_id, action_taken, mode, details))
        response_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return response_id

    def get_recent_events(self, limit=100):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM fim_events ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_recent_attestations(self, limit=50):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM attestation_logs ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_recent_incidents(self, limit=50):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        
        incidents = []
        for row in rows:
            inc = dict(row)
            try:
                inc["mitre_mapping"] = json.loads(inc["mitre_mapping"]) if inc["mitre_mapping"] else None
            except: pass
            try:
                inc["events_correlated"] = json.loads(inc["events_correlated"]) if inc["events_correlated"] else []
            except: pass
            try:
                inc["attack_graph"] = json.loads(inc["attack_graph"]) if inc["attack_graph"] else {"nodes": [], "edges": []}
            except: pass
            incidents.append(inc)
        return incidents

    def get_recent_responses(self, limit=50):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM responses ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def save_approval(self, approval_data):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO pending_approvals 
            (approval_id, incident_id, timestamp, threat_classification, file_path, process_id, process_name, action_type, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            approval_data.get("approval_id"),
            approval_data.get("incident_id"),
            approval_data.get("timestamp"),
            approval_data.get("threat_classification"),
            approval_data.get("file_path"),
            approval_data.get("process_id"),
            approval_data.get("process_name"),
            approval_data.get("action_type"),
            approval_data.get("status", "pending")
        ))
        conn.commit()
        conn.close()

    def get_pending_approvals(self):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pending_approvals WHERE status = 'pending' ORDER BY timestamp DESC")
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows

    def get_approval(self, approval_id):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pending_approvals WHERE approval_id = ?", (approval_id,))
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None

    def update_approval_status(self, approval_id, status):
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE pending_approvals SET status = ? WHERE approval_id = ?", (status, approval_id))
        conn.commit()
        conn.close()

    def get_incident(self, incident_id):
        conn = self.get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        inc = dict(row)
        try:
            inc["events_correlated"] = json.loads(inc["events_correlated"]) if inc["events_correlated"] else []
        except:
            inc["events_correlated"] = []
        return inc

