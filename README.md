# SDN Defender

**SDN Defender** is an SDN-based security application that performs **adaptive DoS/DDoS detection and mitigation**
using **Ryu (OpenFlow 1.3)** and a **Mininet/Open vSwitch** emulated environment.

Project developed for the course **Networks & Cloud Infrastructures** (MSc Computer Engineering, University of Naples Federico II).

----

## Key Features

- **Traffic monitoring** via OpenFlow **PortStats** and **FlowStats**
- **Adaptive thresholds** using **EWMA** (dynamic baseline instead of static thresholds)
- Detection of **burst/stealth** anomalous traffic patterns
- **Progressive mitigation**:
  - `LIMIT` using **OpenFlow meters** (rate limiting)
  - `BLOCK` by installing **drop rules**
  - automatic **UNBLOCK** after a cooldown interval
- **Aggregated DDoS detection** towards a victim destination with **temporary blackhole** mitigation across switches
- **REST API** to manage **whitelist** and **blocklist**
- Optional CLI tooling via shell aliases for quick demo/operations

---

## Architecture (high-level)

The system is structured in modular components:

- `__init__.py`: package initialization (module organization / exports)
- `models.py`: shared data models / structures used across the project
- `controller_app.py`: Ryu app (datapath registration, packet-in handling, REST endpoints)
- `monitor.py`: periodic polling of flow/port statistics
- `policy.py`: detection logic and decision engine (EWMA + escalation)
- `enforcement.py`: mitigation on the data plane (meters, drop rules, blackhole)
- `datastore.py`: shared state and time-series tracking
- `config.py`: global configuration parameters

---

## Requirements

Typical setup (tested in SDN labs / Ubuntu environments):

- Python 3.x
- Ryu SDN Framework
- Mininet
- Open vSwitch (OVS)

---

## How to Run (example)

### 1) Start the Ryu controller
```bash
ryu-manager sdn_defender/controller_app.py
