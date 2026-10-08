# 🛰️ Physical Hardware Evaluation Guide
## Companion-Grade Decentralized Post-Quantum UAV Swarm Node

This package contains the **pure physical hardware evaluation software** for deployment onto physical UAV companion computers (e.g. Raspberry Pi 4/5, NVIDIA Jetson Nano/Orin, Pixhawk companion boards).

> [!NOTE]
> All simulation-only UI tools and automated artificial attack triggers have been completely excluded. All cyber attacks are executed manually via discrete attack tools. The only autonomous background event is the **10.0-second silent heartbeat timeout failover** (Sajid et al. Eq. 4).

---

## 📁 Hardware Package Structure

```text
hardware_evaluation/
├── drone_node.py              # Autonomous Physical UAV Companion Node Daemon
├── mavlink_interface.py       # Robust Real-Time MAVLink Interface for Cube Orange
├── drone_navigation_test.py   # Autonomous 4-Waypoint Drone Navigation & Landing
├── broker_server.py           # Lightweight Decentralized MQTT Mesh Broker
├── protocol.py                # NIST FIPS 203 Hybrid PQC + Anti-Replay Engine
├── comm_benchmark_pqc.py      # Quantitative Hardware Latency Benchmark
├── requirements.txt           # Pip dependencies for Linux/ARM/Raspberry Pi
├── HARDWARE_DEPLOYMENT_GUIDE.md
├── ai/
│   ├── peer_ids_engine.py     # Edge AI IDS (XGBoost + Isolation Forest + Conformal ICP)
│   ├── peer_trust_manager.py  # Asymmetric EMA Trust Evaluator
│   ├── swarm_adaptive_controller.py # 3-Stage Security Ladder Controller
│   ├── energy_manager.py      # Battery Voltage Capping Monitor
│   └── session_manager.py     # 0-RTT Session Resumption Vault
├── encryption/
│   └── aes_encryption.py      # AES-256-GCM Authenticated Encryption
├── key_encapsulation/
│   ├── crystalskyber.py       # ML-KEM-512 / 768 / 1024 Implementation
│   ├── ecc.py                 # SECP256R1 ECDH Key Exchange
│   └── hybrid_kem.py          # Dynamic HKDF Secret Combiner (alpha = 1 - T)
├── models/                    # Pretrained AI IDS and Conformal Calibration models
└── attacks/                   # Manual Hardware Cyber Attack Executables
    ├── spoof_attack.py        # GPS Telemetry & Velocity Spoofing
    ├── replay_attack.py       # Cryptographic Packet Replay Attack
    ├── flooding_attack.py     # High-Rate DoS Telemetry Flooding
    ├── unauthorized_peer.py   # Unauthenticated Rogue Node Injection
    └── unauthorized_client.py # Raw TCP Socket Adversary Attack
```

---

## 🚀 1. Hardware Setup & Installation

Run this on each Raspberry Pi / Companion Computer:

```bash
# 1. Update and install system dependencies
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv git

# 2. Navigate to deployment folder
cd ~/hardware_evaluation

# 3. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 4. Install requirements
pip install -r requirements.txt
```

---

## 🌐 2. Network Topology & Execution

Assign static IP addresses over your Wi-Fi Mesh / Ad-Hoc / Tailscale LAN:
- **Drone 1 (Alpha)**: `192.168.1.101`
- **Drone 2 (Bravo)**: `192.168.1.102`
- **Drone 3 (Charlie)**: `192.168.1.103`
- **Backup Drone (Standby)**: `192.168.1.104`

---

### Step 2.1: Start Local Broker on Each Drone
On each drone (in background or systemd service):
```bash
python3 broker_server.py --host 0.0.0.0 --port 1883
```

---

- **On Drone 1 (`192.168.1.101`) with Cube Orange**:
  ```bash
  python3 drone_node.py --id drone_1 --role primary --broker 192.168.1.101 --port 1883 --peers 192.168.1.102 192.168.1.103 192.168.1.104 --mavlink /dev/ttyACM0 --mavlink-baud 57600
  ```

- **On Drone 2 (`192.168.1.102`) with Cube Orange**:
  ```bash
  python3 drone_node.py --id drone_2 --role primary --broker 192.168.1.102 --port 1883 --peers 192.168.1.101 192.168.1.103 192.168.1.104 --mavlink /dev/ttyACM0 --mavlink-baud 57600
  ```

- **On Drone 3 (`192.168.1.103`) with Cube Orange**:
  ```bash
  python3 drone_node.py --id drone_3 --role primary --broker 192.168.1.103 --port 1883 --peers 192.168.1.101 192.168.1.102 192.168.1.104 --mavlink /dev/ttyACM0 --mavlink-baud 57600
  ```

- **On Standby Backup Drone (`192.168.1.104`) with Cube Orange** (or Multi-Candidate Fleet):
  ```bash
  # Single Standby Drone:
  python3 drone_node.py --id backup_drone --role backup --broker 192.168.1.104 --port 1883 --peers 192.168.1.101 192.168.1.102 192.168.1.103 --mavlink /dev/ttyACM0 --mavlink-baud 57600 --battery 12.50 --health 0.98 --gps-strength 0.95

  # Or Multiple Candidate Backup Drones Competing Independently (Algorithm 1):
  python3 drone_node.py --id backup_drone_1 --role backup --broker 192.168.1.104 --port 1883 --peers 192.168.1.101 192.168.1.102 192.168.1.103 --battery 12.55 --health 0.98 --gps-strength 0.98
  python3 drone_node.py --id backup_drone_2 --role backup --broker 192.168.1.104 --port 1883 --peers 192.168.1.101 192.168.1.102 192.168.1.103 --battery 12.10 --health 0.90 --gps-strength 0.92
  python3 drone_node.py --id backup_drone_3 --role backup --broker 192.168.1.104 --port 1883 --peers 192.168.1.101 192.168.1.102 192.168.1.103 --battery 11.90 --health 0.86 --gps-strength 0.88
  ```

> [!TIP]
> **Cube Orange Connection Options**:
> - **Direct USB Cable (Recommended)**: `--mavlink /dev/ttyACM0` (Raspberry Pi/Linux) or `--mavlink COM3` (Windows)
> - **TELEM1 / TELEM2 UART Header**: `--mavlink /dev/ttyAMA0` or `/dev/serial0` (Raspberry Pi GPIO UART)
> - **SITL / UDP Simulator Bridge**: `--mavlink udp:127.0.0.1:14550`
> - **Bench Testing (Props Off)**: Add `--force-arm` to bypass ArduPilot pre-arm safety checks.
> - **Flight Parameters**: `--takeoff-alt 5.0` (takeoff height in m), `--speed 3.0` (speed in m/s), `--radius 2.0` (acceptance radius).
>
> **Interactive Commands on Node Console**:
> - Press **`b` + Enter**: Triggers immediate on-site **Emergency Landing** (sends physical `MAV_CMD_NAV_LAND` / switches Cube Orange to `LAND` mode) and summons the Backup Drone.
> - Press **`t` + Enter**: Manually arms and initiates GUIDED takeoff to the target altitude.
> - Type **`status` + Enter**: Prints real-time GPS coordinates, Cube Orange battery voltage, and MAVLink connection health.
> - Type **`q` + Enter**: Safely terminates the companion node daemon.

---

## ⚔️ 3. Executing Real Hardware Cyber Attacks

Execute manual attacks from any drone terminal to observe real-time edge security reactions:

### 3.1 GPS Spoofing Attack from Drone 2 targeting Drone 3
```bash
python3 attacks/spoof_attack.py --broker 192.168.1.103 --attacker-id drone_2 --count 15
```
**Outcome on Drone 3**:
- AI IDS flags kinematic velocity jump ($>45\text{ m/s}$)
- Escalates `ML-KEM-512` $\to$ `ML-KEM-768` $\to$ `ML-KEM-1024`
- Drone 2 is quarantined ($T < 0.30$), session keys revoked, and MQTT unsubscribed.
- Backup Drone activates and assumes mission (`ACTIVE_BACKUP -> drone_2`).

### 3.2 High-Rate DoS Telemetry Flooding from Drone 2 targeting Drone 3
```bash
python3 attacks/flooding_attack.py --broker 192.168.1.103 --attacker-id drone_2 --target-drone drone_3 --count 300
```
**Outcome on Drone 3**:
- High RPS anomaly detected ($>50\text{ msg/s}$); rate-limiting protects flight buffer.

### 3.3 Cryptographic Packet Replay Attack targeting Drone 3
```bash
python3 attacks/replay_attack.py --broker 192.168.1.103 --target-drone drone_3
```
**Outcome on Drone 3**:
- Anti-replay sliding window detects non-monotonic sequence numbers and drops replayed packets ($100\%$ drop rate).

### 3.4 Unauthorized Rogue Node Intrusion
```bash
python3 attacks/unauthorized_peer.py --broker 192.168.1.103 --fake-id fake_drone_99
```
**Outcome on Drone 3**:
- Prints `SECURITY ACTION: Connection Refused & Missing PQC Credentials`. Access denied.

---

## 💀 4. Hardware Fault Failover (10s Silent Timeout - Sajid Eq. 4)

1. Kill the node on Drone 1 (`Ctrl+C` or pull power/network).
2. The Backup Drone observes zero heartbeats from `drone_1`.
3. At exactly $t = 10.0\text{s}$, the Backup Drone prints:
   ```text
   TIMEOUT TRIGGER: Primary drone_1 silent for 10.0s!
   *** AUTONOMOUS BACKUP MISSION TAKEOVER ACTIVATED *** (Replacing DRONE_1)
   ```
4. Backup Drone takes over Waypoint flight path.

---

## 📊 5. Benchmark Performance on Hardware

Run the benchmark on your Raspberry Pi / Jetson to get authentic ARM performance metrics:

```bash
python3 comm_benchmark_pqc.py --trials 25 --output arm_pqc_benchmark.csv
```
