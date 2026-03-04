# SDN Defender
 
**SDN Defender** is a Software Defined Networking (SDN) security application designed to perform **adaptive detection and mitigation of DoS/DDoS attacks** in programmable networks.
 
The system leverages the **Ryu SDN Framework** controller and the **OpenFlow** protocol (version 1.3) to dynamically monitor network traffic and apply mitigation strategies in an emulated environment based on **Mininet** and **Open vSwitch**.
 
This project was developed for the course **Networks & Cloud Infrastructures** within the **MSc in Computer Engineering at the University of Naples Federico II**.
 
---
 
# Project Overview
 
Modern networks require dynamic mechanisms to detect abnormal traffic patterns and respond quickly to potential attacks.
 
**SDN Defender** implements a modular SDN controller application capable of:
 
- monitoring network traffic statistics

- detecting anomalies using adaptive thresholds

- applying mitigation policies dynamically in the data plane

- providing a REST interface for network operators
 
The system can identify **DoS and distributed DDoS traffic patterns** and react by progressively enforcing traffic control policies such as **rate limiting, blocking rules, and temporary blackhole mitigation**.
 
---
 
# Key Features
 
- **Traffic monitoring** using OpenFlow **PortStats** and **FlowStats**

- **Adaptive thresholds** based on **EWMA (Exponentially Weighted Moving Average)**

- Detection of **burst and stealth traffic anomalies**

- **Progressive mitigation strategy**:

  - `LIMIT` using OpenFlow **meters** (rate limiting)

  - `BLOCK` via installation of **drop flow rules**

  - automatic **UNBLOCK** after a cooldown period

- **Aggregated DDoS detection** targeting a victim host across multiple switches

- **Temporary blackhole mitigation**

- **REST API** to manage whitelist and blocklist

- Optional CLI utilities for quick interaction with the controller
 
---
 
# Technologies
 
- Python 3

- Ryu SDN Framework

- OpenFlow 1.3

- Mininet

- Open vSwitch

- REST API
 
---
 
# Architecture
 
```

sdn_defender/

│

├── __init__.py

├── models.py

├── controller_app.py

├── monitor.py

├── policy.py

├── enforcement.py

├── datastore.py

└── config.py

```
 
### Modules
 
**__init__.py**  

Package initialization.
 
**models.py**  

Shared data structures used across modules.
 
**controller_app.py**  

Main Ryu controller application handling datapaths, Packet-In events and REST API.
 
**monitor.py**  

Collects OpenFlow statistics periodically.
 
**policy.py**  

Implements anomaly detection logic and mitigation decisions.
 
**enforcement.py**  

Applies mitigation rules to the switches.
 
**datastore.py**  

Maintains runtime data structures and metrics.
 
**config.py**  

Central configuration parameters.
 
---
 
# Requirements
 
Typical testing environment:
 
- Linux (Ubuntu recommended)

- Python 3.x

- Ryu SDN Framework

- Mininet

- Open vSwitch
 
---
 
# How to Run
 
### Start the controller
 
```bash

ryu-manager sdn_defender/controller_app.py

```
 
### Start the Mininet topology
 
```bash

sudo python3 topology/topology_wide.py

```
 
---
 
# CLI Utilities (Optional)
 
The project includes a helper script that installs **bash aliases** to easily interact with the controller's REST API.
 
### Setup (run once)
 
Make the script executable:
 
```bash

chmod +x setup_sdn_alias.sh

```
 
Run the setup script:
 
```bash

./setup_sdn_alias.sh

```
 
This script modifies the **.bashrc** file so that the helper functions are automatically loaded whenever a new terminal is opened.
 
If needed, the aliases can be removed using:
 
```bash

./remove_sdn_alias.sh

```
 
### Optional dependency
 
Install **jq** to visualize JSON responses:
 
```bash

sudo apt install jq -y

```
 
---
 
# Available CLI Commands
 
### Add MAC to whitelist
 
```bash

wl 00:00:00:00:00:01

```
 
### Remove MAC from whitelist
 
```bash

unwl 00:00:00:00:00:01

```
 
### Block a flow
 
```bash

bl 1 1 00:00:00:00:00:01 00:00:00:00:00:03

```
 
### Unblock a flow
 
```bash

unbl 1 1 00:00:00:00:00:01 00:00:00:00:00:03

```
 
### Show whitelist
 
```bash

list_wl

```
 
### Show blocked flows
 
```bash

list_bl

```
 
### Show helper
 
```bash

sdnhelp

```
 
Example output:
 
```

=== SDN Defender Quick Commands ===
 
wl <mac>                                → add MAC to whitelist

unwl <mac>                              → remove MAC from whitelist

bl <dpid> <in_port> <src_mac> <dst_mac>  → block a flow

unbl <dpid> <in_port> <src_mac> <dst_mac>→ unblock a flow

list_wl                                 → show whitelist

list_bl                                 → show blocked flows

```
 
---
 
# Project Report
 
Detailed documentation is available in:
 
```

docs/Report_Cuomo_Tufo_Prisco.pdf

```
 
---
 
# Authors
 
- Matteo Cuomo  

- Antonio Tufo  

- Francesco Prisco  
 
MSc Computer Engineering  

University of Naples Federico II
 
---
 
# License
 
MIT License
 
