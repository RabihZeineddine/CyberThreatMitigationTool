import scapy.all as scapy
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import logging
import time

# Configure logging for security events
logging.basicConfig(filename="security_events.log", level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def log_security_event(event):
    logging.info(event)
    print(f"[ALERT] {event}")

# Simulated network traffic data collection
def capture_packets(packet_count=100):
    packets = scapy.sniff(count=packet_count, prn=lambda x: x.summary(), timeout=30)
    return packets

# Feature extraction from packets
def extract_features(packets):
    data = []
    for pkt in packets:
        features = {
            "packet_size": len(pkt),
            "protocol": pkt.proto if hasattr(pkt, "proto") else 0,
            "src_port": pkt.sport if hasattr(pkt, "sport") else 0,
            "dst_port": pkt.dport if hasattr(pkt, "dport") else 0,
            "ttl": pkt.ttl if hasattr(pkt, "ttl") else 0
        }
        data.append(features)
    return pd.DataFrame(data)

# Train anomaly detection model
def train_anomaly_detector(normal_traffic):
    model = IsolationForest(n_estimators=100, contamination=0.1)
    model.fit(normal_traffic)
    return model

# Detect anomalies
def detect_anomalies(model, new_traffic):
    predictions = model.predict(new_traffic)
    anomalies = new_traffic[predictions == -1]
    return anomalies

if __name__ == "__main__":
    print("Capturing normal traffic for training...")
    normal_packets = capture_packets(packet_count=200)
    normal_data = extract_features(normal_packets)
    model = train_anomaly_detector(normal_data)
    
    print("Monitoring network traffic...")
    while True:
        packets = capture_packets(packet_count=50)
        traffic_data = extract_features(packets)
        anomalies = detect_anomalies(model, traffic_data)
        
        if not anomalies.empty:
            log_security_event(f"Detected {len(anomalies)} anomalous network activities! Possible intrusion attempt.")
        
        time.sleep(10)
