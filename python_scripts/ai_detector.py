import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import os
import joblib  # Added for saving models

CSV_FILE_PATH = "suricata_alerts_dataset.csv"

def run_ai_anomaly_detection(file_path):
    if not os.path.exists(file_path):
        print(f"[-] Error: {file_path} not found. Run your CSV script first!")
        return

    print(f"[*] Loading dataset: {file_path}")
    df = pd.read_csv(file_path)

    if len(df) < 5:
        print("[-] Error: Dataset is too small for AI training. Generate more traffic first!")
        return

    print(f"[*] Processing {len(df)} logs for AI features...")

    # Feature Engineering: Convert text columns into numerical data
    le_source = LabelEncoder()
    le_signature = LabelEncoder()

    df['Source_IP'] = df['Source_IP'].fillna('Unknown')
    df['Signature'] = df['Signature'].fillna('Unknown')
    df['Source_Port'] = pd.to_numeric(df['Source_Port'], errors='coerce').fillna(0)
    df['Dest_Port'] = pd.to_numeric(df['Dest_Port'], errors='coerce').fillna(0)

    # Encode categories into numbers
    df['Src_IP_Encoded'] = le_source.fit_transform(df['Source_IP'])
    df['Sig_Encoded'] = le_signature.fit_transform(df['Signature'])

    # Select features
    features = ['Severity', 'Source_Port', 'Dest_Port', 'Src_IP_Encoded', 'Sig_Encoded']
    X = df[features]

    print("[*] Training Isolation Forest AI Model...")
    model = IsolationForest(contamination=0.05, random_state=42)
    df['Anomaly_Score'] = model.fit_predict(X)

    anomalies = df[df['Anomaly_Score'] == -1]

    print("\n" + "="*80)
    print(f" AI ANOMALY DETECTION REPORT")
    print("="*80)
    print(f"[+] Total Logs Analyzed: {len(df)}")
    print(f"[!] Anomalies Isolated : {len(anomalies)}")
    print("="*80 + "\n")

    # === SAVE MODELS FOR LIVE DEFENDER ===
    print("[*] Exporting AI components for live defender...")
    joblib.dump(model, 'isolation_forest_model.pkl')
    joblib.dump(le_source, 'le_source.pkl')
    joblib.dump(le_signature, 'le_signature.pkl')
    print("[+] Export Complete: Saved models to active directory.")

    if not anomalies.empty:
        print("\n[!] TOP SUSPICIOUS NETWORK EVENTS FOUND BY AI:")
        print("-" * 80)
        print(anomalies[['Timestamp', 'Source_IP', 'Dest_Port', 'Signature', 'Severity']].head(10).to_string(index=False))
        anomalies.to_csv("isolated_anomalies.csv", index=False)
        print("\n[+] Saved anomalous events to 'isolated_anomalies.csv' for immediate investigation.")
    else:
        print("[+] AI Analysis Complete: Everything matches normal baseline patterns.")

if __name__ == "__main__":
    run_ai_anomaly_detection(CSV_FILE_PATH)
