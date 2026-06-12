# realtime_ids_v2.py
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

import pandas as pd
import joblib
import threading
import time
import csv
import os

from datetime import datetime
from threading import Lock

FLOW_TIMEOUT = 10
PREDICTION_INTERVAL = 3
STATUS_INTERVAL = 30
ALERT_COOLDOWN = 60

print("\nLoading model...")

model = joblib.load("models/random_forest_ids_multiclass.pkl")
scaler = joblib.load("models/random_forest_scaler_multiclass.pkl")

print("Model loaded successfully.")

label_map = {
    0: "NORMAL",
    1: "PORTSCAN",
    2: "SSH_BRUTEFORCE"
}

flows = {}
flows_lock = Lock()

recent_alerts = {}
alerts_lock = Lock()

suppressed_portscan = 0
suppressed_ssh = 0

os.makedirs("logs", exist_ok=True)
HISTORY_FILE = "logs/alerts_history.csv"
SESSION_FILE = "logs/alerts_session.csv"

if not os.path.exists(HISTORY_FILE):
    with open(HISTORY_FILE, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            "timestamp","src_ip","dst_ip",
            "src_port","dst_port","prediction"
        ])

with open(SESSION_FILE, "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow([
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "prediction"
    ])

def create_bidirectional_key(src_ip,dst_ip,src_port,dst_port,protocol):
    endpoint1 = (src_ip, src_port)
    endpoint2 = (dst_ip, dst_port)
    if endpoint1 <= endpoint2:
        return (endpoint1, endpoint2, protocol)
    return (endpoint2, endpoint1, protocol)

def process_packet(packet):
    current_time = time.time()

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ip_version = 4
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        ip_version = 6
    else:
        return

    protocol = "OTHER"
    src_port = 0
    dst_port = 0
    syn_count = ack_count = fin_count = rst_count = 0

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        if flags.S: syn_count = 1
        if flags.A: ack_count = 1
        if flags.F: fin_count = 1
        if flags.R: rst_count = 1

    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    flow_key = create_bidirectional_key(
        src_ip, dst_ip, src_port, dst_port, protocol
    )

    packet_size = len(packet)

    with flows_lock:
        if flow_key not in flows:
            flows[flow_key] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "ip_version": ip_version,
                "start_time": current_time,
                "end_time": current_time,
                "last_seen": current_time,
                "packet_count": 1,
                "total_bytes": packet_size,
                "syn_count": syn_count,
                "ack_count": ack_count,
                "fin_count": fin_count,
                "rst_count": rst_count,
                "protocol": protocol
            }
        else:
            flow = flows[flow_key]
            flow["end_time"] = current_time
            flow["last_seen"] = current_time
            flow["packet_count"] += 1
            flow["total_bytes"] += packet_size
            flow["syn_count"] += syn_count
            flow["ack_count"] += ack_count
            flow["fin_count"] += fin_count
            flow["rst_count"] += rst_count

def build_features(flow):
    duration = flow["end_time"] - flow["start_time"]
    if duration <= 0:
        duration = 0.001

    return pd.DataFrame([{
        "ip_version": flow["ip_version"],
        "duration": duration,
        "packet_count": flow["packet_count"],
        "total_bytes": flow["total_bytes"],
        "avg_packet_size": flow["total_bytes"] / flow["packet_count"],
        "packets_per_sec": flow["packet_count"] / duration,
        "syn_count": flow["syn_count"],
        "ack_count": flow["ack_count"],
        "fin_count": flow["fin_count"],
        "rst_count": flow["rst_count"],
        "protocol_TCP": 1 if flow["protocol"] == "TCP" else 0,
        "protocol_UDP": 1 if flow["protocol"] == "UDP" else 0
    }])

def save_alert(flow, prediction_name):

    alert_row = [
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        flow["src_ip"],
        flow["dst_ip"],
        flow["src_port"],
        flow["dst_port"],
        prediction_name
    ]

    # Permanent archive
    with open(HISTORY_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(alert_row)

    # Current IDS session only
    with open(SESSION_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(alert_row)

def prediction_loop():
    global suppressed_portscan, suppressed_ssh

    while True:
        time.sleep(PREDICTION_INTERVAL)

        with flows_lock:
            flow_items = list(flows.items())

        expired = []
        current_time = time.time()

        for flow_key, flow in flow_items:

            X = build_features(flow)
            pred = model.predict(scaler.transform(X))[0]

            if pred in [1, 2]:
                attack_name = label_map[pred]
                alert_key = (flow["src_ip"], attack_name)

                should_alert = False

                with alerts_lock:
                    if alert_key not in recent_alerts:
                        should_alert = True
                    elif current_time - recent_alerts[alert_key] > ALERT_COOLDOWN:
                        should_alert = True

                    if should_alert:
                        recent_alerts[alert_key] = current_time

                if should_alert:
                    print(f"\n⚠ {attack_name} DETECTED")
                    print(f"Source IP : {flow['src_ip']}")
                    print(f"Target IP : {flow['dst_ip']}")
                    save_alert(flow, attack_name)
                else:
                    if pred == 1:
                        suppressed_portscan += 1
                    else:
                        suppressed_ssh += 1

            if current_time - flow["last_seen"] > FLOW_TIMEOUT:
                expired.append(flow_key)

        if expired:
            with flows_lock:
                for key in expired:
                    flows.pop(key, None)

def status_loop():
    while True:
        time.sleep(STATUS_INTERVAL)

        with flows_lock:
            current_flows = list(flows.values())

        active_normal = 0
        active_portscan = 0
        active_ssh = 0

        for flow in current_flows:
            X = build_features(flow)
            pred = model.predict(scaler.transform(X))[0]

            if pred == 0:
                active_normal += 1
            elif pred == 1:
                active_portscan += 1
            elif pred == 2:
                active_ssh += 1

        os.system("clear")

        print("=================================")
        print(" REAL-TIME IDS STATUS ")
        print("=================================")
        print(f"\nActive Flows    : {len(current_flows)}")
        print(f"Normal          : {active_normal}")
        print(f"Portscan        : {active_portscan}")
        print(f"SSH Bruteforce  : {active_ssh}")
        print("\nSuppressed Alerts")
        print(f"Portscan : {suppressed_portscan}")
        print(f"SSH      : {suppressed_ssh}")
        print("\n=================================")

print("\n=================================")
print(" REAL-TIME ML IDS STARTED ")
print("=================================")

threading.Thread(target=prediction_loop, daemon=True).start()
threading.Thread(target=status_loop, daemon=True).start()

sniff(prn=process_packet, store=False)
