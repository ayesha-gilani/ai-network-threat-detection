import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load your processed anomaly dataset
try:
    df = pd.read_csv("suricata_alerts_dataset.csv")
    # Since we know your contamination was 5%, let's simulate the model scores for charting if not appended
    if 'Anomaly_Score' not in df.columns:
        # If you have isolated_anomalies.csv, we can mark them
        df['Anomaly'] = 'Normal'
        anom_df = pd.read_csv("isolated_anomalies.csv")
        df.loc[df['Timestamp'].isin(anom_df['Timestamp']), 'Anomaly'] = 'Anomaly'
    else:
        df['Anomaly'] = df['Anomaly_Score'].apply(lambda x: 'Anomaly' if x == -1 else 'Normal')

    plt.figure(figsize=(10, 6))
    sns.scatterplot(data=df, x='Source_Port', y='Dest_Port', hue='Anomaly', palette={'Normal': 'blue', 'Anomaly': 'red'}, alpha=0.6)
    plt.title('AI Threat Detection: Isolation Forest Outlier Boundaries')
    plt.xlabel('Source Port Connection Ranks')
    plt.ylabel('Destination Port Target Plane')
    plt.grid(True)

    # Save chart as image
    plt.savefig('ai_detection_boundary.png', dpi=300)
    print("[+] Presentation chart generated successfully as 'ai_detection_boundary.png'!")
except Exception as e:
    print(f"[-] Visualization failed: {e}")
