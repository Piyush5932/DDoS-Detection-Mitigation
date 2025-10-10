# DDoS Attack Detection and Mitigation

A Software Defined Networking (SDN) based solution for detecting and mitigating Distributed Denial of Service (DDoS) attacks using Machine Learning.

## Overview

This project implements a DDoS attack detection and mitigation system using:
- SDN architecture with os-ken controller (maintained fork of Ryu)
- Mininet for network simulation
- Machine Learning (Random Forest) for attack detection
- Real-time traffic monitoring and mitigation

## Features

- Network traffic monitoring and feature extraction
- Machine learning-based DDoS attack detection
- Automatic attack mitigation through flow rule installation
- Support for detecting various DDoS attack types (ICMP flood, SYN flood, UDP flood)
- Compatible with latest Ubuntu and Python versions
- Enhanced attack visualization with detailed metrics
- Real-time attack detection alerts and mitigation confirmation

## Requirements

### Linux Environment
- Ubuntu (Latest version)
- Python 3.8+
- Mininet
- os-ken (OpenStack's maintained fork of Ryu)
- scikit-learn
- pandas
- numpy
- hping3 (for attack simulation)

### Windows Environment
- Python 3.8+
- os-ken
- scikit-learn
- pandas
- numpy
- socket (for simulation testing)

## Installation

### Linux Installation (Full Functionality)

1. Install required system packages:
```bash
sudo apt update
sudo apt install -y mininet python3-pip git python3-venv python3-full
```

2. Create a virtual environment and install Python packages:
```bash
# Create a virtual environment
python3 -m venv ddos_env
# Activate the virtual environment
source ddos_env/bin/activate
# Install required Python packages
pip install os-ken pandas numpy scikit-learn matplotlib
```

3. Clone this repository:
```bash
git clone https://github.com/yourusername/DDoS-Detection-Mitigation.git
cd DDoS-Detection-Mitigation
```

Note: Always activate the virtual environment before running the controller:
```bash
source ~/ddos_env/bin/activate
```

### Windows Installation (Limited Functionality)

1. Install Python from the [official website](https://www.python.org/downloads/)

2. Install required packages:
```powershell
pip install os-ken pandas numpy scikit-learn matplotlib
```

3. Clone or download this repository

## Usage

### Linux Usage (Full Functionality)

1. Start the os-ken controller:
```bash
cd controller
python3 controller.py
```

2. In a separate terminal, start the Mininet topology:
```bash
cd mininet
sudo python3 topology.py
```

3. To simulate attacks (from Mininet CLI):
```bash
# ICMP flood
h1 hping3 -1 -V -d 120 -w 64 -p 80 --rand-source --flood h2

# SYN flood
h1 hping3 -S -V -d 120 -w 64 -p 80 --rand-source --flood h2

# UDP flood
h1 hping3 -2 -V -d 120 -w 64 -p 80 --rand-source --flood h2
```

### Windows Usage (Limited Functionality)

1. Start the test controller for attack detection:
```powershell
cd controller
python test_controller.py
```
You should see output like:
```
INFO - Simple DDoS Detection Controller Started
INFO - Controller listening on 127.0.0.1:6653
```

2. In a separate terminal, run the attack simulation:
```powershell
cd controller
python quick_attack_test.py
```
You should see output like:
```
Starting quick attack test...
Starting TCP flood attack to 127.0.0.1:6653
Sent 0 attack packets
Sent 10 attack packets
...
Attack completed
```

3. Check the test controller terminal for attack detection messages:
```
WARNING - ATTACK DETECTED: TCP Flood from 127.0.0.1 (Rate: 306.20 pps)
WARNING - BLOCKING SOURCE: 127.0.0.1
INFO - Blocked connection attempt from 127.0.0.1
```

Note: If you don't see attack detection messages, try running the attack simulation again or increase the number of packets in quick_attack_test.py.

4. Monitoring attack detection:
When an attack is detected, you'll see clear alerts in the controller terminal:
```
============================================================
🚨 DDOS ATTACK DETECTED! 🚨
============================================================

Attack Details:
  Source IP:       192.168.1.2
  Destination IP:  192.168.1.3
  Protocol:        ICMP
  Confidence:      98.75%
  Packets/sec:     520.7
  Bytes/sec:       52000

✅ MITIGATION ACTION: Blocked source IP 192.168.1.2
============================================================
```

## Project Structure

```
DDoS-Detection-Mitigation/
├── controller/
│   ├── controller.py       # Main os-ken controller application
│   ├── ml_model.py         # Machine learning model implementation
│   └── feature_extractor.py # Traffic feature extraction
├── mininet/
│   └── topology.py         # Network topology definition
├── dataset/
│   └── traffic_data.csv    # Generated dataset for training
├── models/
│   └── rf_model.pkl        # Trained Random Forest model
└── README.md
```

## License

MIT License