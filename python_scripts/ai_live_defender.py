import json
import time
import os
import pandas as pd
import joblib

MODEL_PATH = "isolation_forest_model.pkl"
LE_SRC_PATH = "le_source.pkl"
LE_SIG_PATH = "le_signature.pkl"
EVE_PATH = "/var/log/suricata/eve.json"
AI_LOG_PATH = "/var/log/suricata/ai_anomalies.json"

# Load saved components
if os.path.exists(MODEL_PATH) and os.path.exists(LE_SRC_PATH) and os.path.exists(LE_SIG_PATH):
    model = joblib.load(MODEL_PATH)
    le_source = joblib.load(LE_SRC_PATH)
    le_signature = joblib.load(LE_SIG_PATH)
    print("[+] Pre-trained AI Components loaded successfully!")
else:
    raise FileNotFoundError("[-] Missing pickle files. Run updated ai_detector.py first.")

def follow_eve_log(filename):
    with open(filename, 'r') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line

def extract_live_features(log_data):
    # Extract matching fields
    src_ip = log_data.get('src_ip', 'Unknown')
    signature = log_data.get('alert', {}).get('signature', 'Unknown')
    severity = log_data.get('alert', {}).get('severity', 0)
    src_port = log_data.get('src_port', 0)
    dest_port = log_data.get('dest_port', 0)

    # Handle unseen categories dynamically using label encoders
    try:
        src_encoded = le_source.transform([src_ip])[0]
    except ValueError:
        src_encoded = -1  # Mark new dynamic IP behavior as extreme out-of-bounds anomaly

    try:
        sig_encoded = le_signature.transform([signature])[0]
    except ValueError:
        sig_encoded = -1  # Unseen signatures are inherently anomalous

    features = {
        'Severity': severity,
        'Source_Port': src_port,
        'Dest_Port': dest_port,
        'Src_IP_Encoded': src_encoded,
        'Sig_Encoded': sig_encoded
    }
    return pd.DataFrame([features])

def log_anomaly_for_wazuh(log_data):
    payload = {
        "integration": "isolation_forest_ai",
        "status": "malicious_anomaly",
        "src_ip": log_data.get("src_ip", "0.0.0.0"),
        "dest_ip": log_data.get("dest_ip", "0.0.0.0"),
        "signature": log_data.get("alert", {}).get("signature", "Unknown Alert"),
        "severity": log_data.get("alert", {}).get("severity", 1)
    }
    with open(AI_LOG_PATH, "a") as f:
        f.write(json.dumps(payload) + "\n")

def run_live_defender():
    print("\n" + "="*80)
    print("🚀 LIVE DEFENDER ACTIVE: Processing Suricata alerts through trained trees...")
    print("="*80 + "\n")
    
    for line in follow_eve_log(EVE_PATH):
        try:
            log_data = json.loads(line)
            if log_data.get("event_type") == "alert":
                X_live = extract_live_features(log_data)
                prediction = model.predict(X_live)[0]
                
                if prediction == -1:
                    print(f"⚠️  [AI ANOMALY] Src: {log_data.get('src_ip')} -> Dest Port: {log_data.get('dest_port')} | {log_data['alert']['signature']}")
                    log_anomaly_for_wazuh(log_data)
        except Exception as e:
            continue

if __name__ == "__main__":
    try:
        run_live_defender()
    except KeyboardInterrupt:
        print("\n[-] Stopping Live Defender.")
