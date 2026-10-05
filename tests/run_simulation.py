import urllib.request
import urllib.parse
import json
import time
import sys

BASE_URL = "http://127.0.0.1:8000"

def post_json(endpoint, data):
    url = f"{BASE_URL}{endpoint}"
    req_data = json.dumps(data).encode('utf-8')
    req = urllib.request.Request(
        url, 
        data=req_data, 
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except Exception as e:
        print(f"Connection error to API: {e}")
        return None

def get_json(endpoint):
    url = f"{BASE_URL}{endpoint}"
    try:
        with urllib.request.urlopen(url) as response:
            return json.loads(response.read().decode())
    except Exception as e:
        print(f"Connection error to API: {e}")
        return None

def check_backend_alive():
    status = get_json("/api/status")
    if status:
        print(f"[+] Security Daemon is ONLINE. Trust Score: {status['system_trust_score']}/100, Threat Level: {status['current_threat_level']}")
        return True
    else:
        print("[-] Security Daemon is OFFLINE. Please start the backend with `python -m src.backend.main` first.")
        return False

def run_scenario(scenario_id, name):
    print("\n" + "="*60)
    print(f"RUNNING SCENARIO {scenario_id}: {name}")
    print("="*60)
    
    # Trigger scenario
    result = post_json("/api/trigger-test", {"scenario_id": scenario_id})
    if not result:
        print("[-] Failed to trigger scenario.")
        return
        
    print(f"[+] Scenario triggered. Processing telemetry pipeline...")
    time.sleep(3) # Wait for FIM pipeline to process files
    
    # Query logs to see details
    incidents = get_json("/api/incidents")
    events = get_json("/api/events")
    responses = get_json("/api/responses")
    attestation = get_json("/api/attestation")
    
    # Report findings
    if scenario_id == 3:
        # Check attestation trust score
        print(f"[+] Attestation Check result:")
        print(f"    - Current Runtime Trust Score: {attestation['current']['score']}")
        print(f"    - Trust State: {attestation['current']['state']}")
        print(f"    - Active Violations: {attestation['current']['violations']}")
    else:
        # Check FIM and incident metrics
        if incidents:
            latest = incidents[0]
            print(f"[+] Latest Incident Detected (INC-#{latest['id']}):")
            print(f"    - Risk Score: {latest['risk_score']}/100")
            print(f"    - Classification: {latest['threat_classification']}")
            print(f"    - MITRE ATT&CK Mapping: {latest['mitre_mapping']}")
            print(f"    - AI Threat Report Summary: {latest['llm_summary']}")
            if latest['mitre_mapping']:
                print(f"    - MITRE Details: {latest['mitre_mapping']['evidence']}")
        else:
            print("[-] No incidents recorded.")
            
    if responses:
        latest_resp = responses[0]
        print(f"[+] Incident Response Record:")
        print(f"    - Action Executed: {latest_resp['action_taken']}")
        print(f"    - Mode: {latest_resp['mode']}")
        print(f"    - Response logs: {latest_resp['details']}")

def main():
    if not check_backend_alive():
        sys.exit(1)
        
    print("\nStarting laboratory test suite...")
    
    # Scenario 1
    run_scenario(1, "Normal File Modification (Expected: Low Risk / Normal)")
    
    # Scenario 2
    run_scenario(2, "Suspicious File Modification on Sensitive Path (Expected: High Risk)")
    
    # Scenario 3
    run_scenario(3, "Runtime Attestation Tampering (Expected: Trust Degradation & Warning)")
    
    # Scenario 4
    run_scenario(4, "Multi-stage Cyber Attack Sequence (Expected: Critical Threat & Block/Isolate)")

if __name__ == "__main__":
    main()
