import os
import time
import json
from datetime import datetime
from collections import deque

class CorrelationEngine:
    def __init__(self, time_window_sec=20):
        self.time_window = time_window_sec
        # Active incident structure:
        # {
        #   "id": None, # assigned when logged
        #   "start_time": isoformat,
        #   "last_update": float_timestamp,
        #   "events": []
        # }
        self.active_incident = None

    def add_event(self, event):
        """
        Processes a FIM event. Correlates it with existing active incidents
        if it falls within the time window. Otherwise, starts a new incident.
        Returns the incident dictionary.
        """
        now = time.time()
        event_time_str = event.get("timestamp", datetime.now().isoformat())
        
        # Check if we should merge into active incident
        if self.active_incident and (now - self.active_incident["last_update"] <= self.time_window):
            self.active_incident["events"].append(event)
            self.active_incident["last_update"] = now
        else:
            # Create a new incident
            self.active_incident = {
                "start_time": event_time_str,
                "last_update": now,
                "events": [event]
            }

        # Build attack graph and summarize incident details
        self.active_incident["attack_graph"] = self.build_attack_graph(self.active_incident["events"])
        self.active_incident["events_correlated"] = [e["id"] for e in self.active_incident["events"]]
        
        return self.active_incident

    def build_attack_graph(self, events):
        """
        Generates nodes and edges representing the relationships of all entities
        involved in the correlated event sequence.
        Format is compatible with Vis.js or Cytoscape.js.
        """
        nodes = {}
        edges = []
        
        for idx, event in enumerate(events):
            user = event.get("username", "Unknown User")
            pid = event.get("process_id")
            pname = event.get("process_name", "Unknown Process")
            ppid = event.get("parent_process_id")
            ppname = event.get("parent_process_name", "Unknown Parent")
            filepath = event.get("file_path", "")
            filename = os.path.basename(filepath)
            event_type = event.get("event_type", "ACCESS")
            cmd = event.get("command_line", "")
            
            # 1. User Node
            user_node_id = f"user_{user}"
            if user_node_id not in nodes:
                nodes[user_node_id] = {
                    "id": user_node_id,
                    "label": f"User: {user}",
                    "group": "user",
                    "title": f"System User: {user}"
                }
                
            # 2. Parent Process Node (if exists)
            parent_node_id = None
            if ppid:
                parent_node_id = f"proc_{ppid}_{ppname}"
                if parent_node_id not in nodes:
                    nodes[parent_node_id] = {
                        "id": parent_node_id,
                        "label": f"{ppname}\n(PID: {ppid})",
                        "group": "parent_process",
                        "title": f"Parent Process: {ppname}\nPID: {ppid}"
                    }
                # Connect User to Parent Process
                edge_id = f"{user_node_id}->{parent_node_id}"
                if not any(e["id"] == edge_id for e in edges):
                    edges.append({
                        "id": edge_id,
                        "from": user_node_id,
                        "to": parent_node_id,
                        "label": "spawned",
                        "color": "#4dabf7"
                    })

            # 3. Culprit Process Node
            proc_node_id = f"proc_{pid}_{pname}" if pid else f"proc_unknown_{pname}"
            if proc_node_id not in nodes:
                nodes[proc_node_id] = {
                    "id": proc_node_id,
                    "label": f"{pname}\n(PID: {pid})",
                    "group": "process",
                    "title": f"Process Name: {pname}\nPID: {pid}\nCommand: {cmd}"
                }
            
            # Connect Parent to Process
            if parent_node_id:
                edge_id = f"{parent_node_id}->{proc_node_id}"
                if not any(e["id"] == edge_id for e in edges):
                    edges.append({
                        "id": edge_id,
                        "from": parent_node_id,
                        "to": proc_node_id,
                        "label": "spawned",
                        "color": "#37b24d"
                    })
            else:
                # Direct connect User to Process
                edge_id = f"{user_node_id}->{proc_node_id}"
                if not any(e["id"] == edge_id for e in edges):
                    edges.append({
                        "id": edge_id,
                        "from": user_node_id,
                        "to": proc_node_id,
                        "label": "spawned",
                        "color": "#4dabf7"
                    })

            # 4. File Node
            file_node_id = f"file_{filepath}"
            if file_node_id not in nodes:
                nodes[file_node_id] = {
                    "id": file_node_id,
                    "label": filename,
                    "group": "file",
                    "title": f"Full Path: {filepath}"
                }
            
            # Connect Process to File
            edge_id = f"{proc_node_id}->{file_node_id}"
            if not any(e["id"] == edge_id for e in edges):
                edges.append({
                    "id": edge_id,
                    "from": proc_node_id,
                    "to": file_node_id,
                    "label": "accessed",
                    "color": "#fcc419"
                })

            # 5. File Event Node (Aggregated per file & event_type to prevent graph congestion)
            event_node_id = f"evt_{file_node_id}_{event_type}"
            if event_node_id not in nodes:
                nodes[event_node_id] = {
                    "id": event_node_id,
                    "label": f"{event_type}\n({event.get('integrity_status', 'Violated')})",
                    "group": "event",
                    "title": f"Time: {event.get('timestamp')}\nHash: {event.get('hash_after')}",
                    "count": 1
                }
                edges.append({
                    "id": f"{file_node_id}->{event_node_id}",
                    "from": file_node_id,
                    "to": event_node_id,
                    "label": "triggered",
                    "color": "#fa5252"
                })
            else:
                nodes[event_node_id]["count"] = nodes[event_node_id].get("count", 1) + 1
                cnt = nodes[event_node_id]["count"]
                nodes[event_node_id]["label"] = f"{event_type} ({cnt}x)\n({event.get('integrity_status', 'Violated')})"
                nodes[event_node_id]["title"] += f"\n---\nTime: {event.get('timestamp')}\nHash: {event.get('hash_after')}"
                for edge in edges:
                    if edge["id"] == f"{file_node_id}->{event_node_id}":
                        edge["label"] = f"triggered ({cnt}x)"


            # 6. Look for Network signatures in command line parameters to add a Network node
            # This handles simulated port opening or curl/nc commands
            cmd_lower = cmd.lower()
            if "curl" in cmd_lower or "wget" in cmd_lower or "nc " in cmd_lower or "netcat" in cmd_lower or "ping" in cmd_lower or "socat" in cmd_lower:
                ip_target = "external_cnc"
                # Check for an IP-like signature
                import re
                ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', cmd)
                if ip_match:
                    ip_target = ip_match.group(0)
                    
                net_node_id = f"net_{ip_target}"
                if net_node_id not in nodes:
                    nodes[net_node_id] = {
                        "id": net_node_id,
                        "label": f"Network C2\n({ip_target})",
                        "group": "network",
                        "title": f"Network transmission command detected: {cmd}"
                    }
                
                # Connect Process to Network target
                edge_id = f"{proc_node_id}->{net_node_id}"
                if not any(e["id"] == edge_id for e in edges):
                    edges.append({
                        "id": edge_id,
                        "from": proc_node_id,
                        "to": net_node_id,
                        "label": "exfiltrated / network connection",
                        "color": "#e8590c"
                    })

        return {
            "nodes": list(nodes.values()),
            "edges": edges
        }
