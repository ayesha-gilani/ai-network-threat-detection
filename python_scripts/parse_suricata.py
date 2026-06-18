import json
import csv
import os

# Paths configuration
LOG_FILE_PATH = "/var/log/suricata/eve.json"
OUTPUT_CSV_PATH = "suricata_alerts_dataset.csv"

def parse_logs_to_csv(json_path, csv_path):
    if not os.path.exists(json_path):
        print(f"[-] Error: File not found at {json_path}")
        return

    print(f"[*] Parsing logs from: {json_path}")
    
    # Define CSV Header row columns
    headers = ["Timestamp", "Severity", "Source_IP", "Source_Port", "Dest_IP", "Dest_Port", "Signature", "Category"]
    
    alert_count = 0

    try:
        # Open CSV file for writing and JSON file for reading
        with open(csv_path, mode='w', newline='', encoding='utf-8') as csv_file, \
             open(json_path, mode='r', encoding='utf-8') as json_file:
            
            writer = csv.writer(csv_file)
            writer.writerow(headers) # Write columns header first
            
            for line in json_file:
                try:
                    log_entry = json.loads(line.strip())
                    
                    if log_entry.get("event_type") == "alert":
                        alert_data = log_entry.get("alert", {})
                        
                        # Extract expanded network dataset features
                        timestamp = log_entry.get("timestamp", "N/A")[:19]
                        severity = alert_data.get("severity", "N/A")
                        src_ip = log_entry.get("src_ip", "N/A")
                        src_port = log_entry.get("src_port", "N/A")
                        dest_ip = log_entry.get("dest_ip", "N/A")
                        dest_port = log_entry.get("dest_port", "N/A")
                        signature = alert_data.get("signature", "N/A")
                        category = alert_data.get("category", "N/A")
                        
                        # Write row to CSV dataset
                        writer.writerow([timestamp, severity, src_ip, src_port, dest_ip, dest_port, signature, category])
                        alert_count += 1
                        
                except json.JSONDecodeError:
                    continue
                    
        print(f"[+] Success! Dataset created successfully: {csv_path}")
        print(f"[+] Total log alerts parsed into dataset: {alert_count}")
        
    except PermissionError:
        print("[-] Permission Denied. Please run this script with 'sudo'.")

if __name__ == "__main__":
    parse_logs_to_csv(LOG_FILE_PATH, OUTPUT_CSV_PATH)
