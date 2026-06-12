# ML-Based Real-Time Network Intrusion Detection System (IDS)

## Overview

This project is a Machine Learning-based Network Intrusion Detection System (IDS) that monitors live network traffic, extracts flow-based network features, classifies traffic using a trained Random Forest model, and displays detected threats through a real-time dashboard.

The system is capable of identifying:

- Normal Network Traffic
- Port Scan Attacks
- SSH Brute Force Attacks

The IDS performs real-time packet capture, flow creation, feature extraction, machine learning-based classification, alert logging, and dashboard visualization.

---

## Features

### Real-Time Traffic Monitoring
- Live packet capture using Scapy
- IPv4 and IPv6 support
- TCP and UDP traffic analysis

### Flow-Based Feature Extraction
The IDS extracts network flow features such as:

- Duration
- Packet Count
- Total Bytes
- Average Packet Size
- Packets Per Second
- SYN Count
- ACK Count
- FIN Count
- RST Count
- Protocol Type

### Machine Learning Detection
- Random Forest Classifier
- Multiclass Classification
- Trained on:
  - Normal Traffic
  - Port Scan Traffic
  - SSH Brute Force Traffic

### Alert Management
- Real-time attack detection
- Alert cooldown mechanism to prevent duplicate alerts
- Session-based logging
- Historical logging

### Dashboard
- Total Alerts
- Port Scan Alerts
- SSH Brute Force Alerts
- Unique Attack Sources
- Attack Distribution Visualization
- Alert Timeline
- Recent Alerts Table
- Log Download Support

---

## System Architecture

```text
Packet Capture
      ↓
Flow Creation
      ↓
Feature Extraction
      ↓
Machine Learning Classification
      ↓
Attack Detection
      ↓
Alert Logging
      ↓
Dashboard Visualization
```

---

## Project Structure

```text
/

├── collector/
│   └── collector.py
│
├── training/
│   └── train_model.py
│
├── models/
│   ├── random_forest_ids_multiclass.pkl
│   ├── random_forest_scaler_multiclass.pkl
│   └── feature_columns.pkl
│
├── logs/
│   ├── alerts_history.csv
│   └── alerts_session.csv
│
├── dashboard/
│   ├── app.py
│   └── .streamlit/
│       └── config.toml
│
├── datasets/
│
├── realtime_ids.py
│
├── requirements.txt
│
└── README.md
```

---

## Technologies Used

- Python
- Scapy
- Pandas
- NumPy
- Scikit-Learn
- Joblib
- Streamlit
- Plotly

---

## Installation


### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Running the IDS

Start the real-time intrusion detection engine:

```bash
sudo python3 realtime_ids.py
```

The IDS will begin monitoring network traffic and logging detected attacks.

---

## Running the Dashboard

Open a new terminal and run:

```bash
cd dashboard

streamlit run app.py
```

Then open:

```text
http://localhost:8501
```

---

## Attack Classes

| Label | Attack Type |
|---------|-------------|
| 0 | Normal Traffic |
| 1 | Port Scan |
| 2 | SSH Brute Force |

---

## Logging System

The IDS maintains two separate log files:

### alerts_history.csv

Permanent archive containing all detected attacks.

### alerts_session.csv

Session-specific log recreated each time the IDS starts.

The dashboard reads from the session log to provide a clean demonstration environment.

---

## Example Detection Output

```text
⚠ PORTSCAN DETECTED

Source IP : 192.168.31.70
Target IP : 192.168.31.175
```

```text
⚠ SSH_BRUTEFORCE DETECTED

Source IP : 192.168.31.70
Target IP : 192.168.31.175
```

---

## Future Improvements

- Raspberry Pi Deployment
- Edge-Based Intrusion Detection
- Additional Attack Classes
- Email/SMS Alerting
- Remote Dashboard Access
- SIEM Integration
- Cloud Logging Support

---

## Educational Purpose

This project was developed as a cybersecurity and machine learning learning project to demonstrate:

- Network Traffic Analysis
- Feature Engineering
- Machine Learning for Security
- Real-Time Intrusion Detection
- Security Dashboard Development

---

## License

This project is licensed under the MIT License.