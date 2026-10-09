"""
swarm_node.py — Decentralized Autonomous UAV Node with Post-Quantum Security & AI IDS
=====================================================================================
Integrates:
1. Decentralized Peer-to-Peer Mesh Networking (Zero-SPOF)
2. Mutual Hybrid Post-Quantum Cryptography (ECC-P256 + CRYSTALS-Kyber KEM)
3. Dynamic Trust-Weighted Secret Derivation (alpha = 1.0 - Trust)
4. Local AI Intrusion Detection Engine (XGBoost + Isolation Forest + Conformal Prediction)
5. 3-Tier Security Ladder Escalation (ML-KEM 512 -> 768 -> 1024)
6. 0-RTT Session Resumption & Physical Battery/CPU Energy Gating
7. Autonomous Backup Drone Takeover upon Node Crash or Rogue Isolation (Sajid et al. Eq. 4)
"""

import os
import sys
import time
import json
import uuid
import math
import random
import argparse
import threading
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

# Adjust module path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from protocol import MessageType, SwarmPacket, DecentralizedProtocolEngine
from encryption.aes_encryption import encrypt_data, decrypt_data
from key_encapsulation.crystalskyber import generate_kyber_keypair, encapsulate_kyber, decapsulate_kyber
from key_encapsulation.ecc import generate_private_key, get_public_key, get_shared_key
from key_encapsulation.hybrid_kem import combine_secrets, trust_to_alpha
from ai.peer_trust_manager import PeerTrustManager
from ai.peer_ids_engine import PeerIDSEngine
from ai.swarm_adaptive_controller import SwarmAdaptiveController
from ai.energy_manager import EnergyManager
from ai.session_resumption import SessionTicketManager
from ai.optimal_backup_selector import OptimalBackupSelector, BackupCandidateState, haversine_distance_m


# Default RGUKT Nuzvid Campus Reference Waypoints
WAYPOINT_COORDS = [
    {"lat": 16.792406, "lon": 80.819767, "alt": 5.0},
    {"lat": 16.792440, "lon": 80.820356, "alt": 5.0},
    {"lat": 16.792455, "lon": 80.821035, "alt": 5.0},
    {"lat": 16.792820, "lon": 80.820500, "alt": 5.0},
    {"lat": 16.793200, "lon": 80.819800, "alt": 5.0}
]

PRINT_LOCK = threading.Lock()

def safe_log(prefix: str, msg: str):
    with PRINT_LOCK:
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{ts}] {prefix} {msg}", flush=True)


def ensure_local_broker(host: str = "127.0.0.1", port: int = 1883) -> bool:
    """Checks if MQTT broker is listening on host:port. If localhost and closed, auto-starts embedded mesh broker."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        res = s.connect_ex((host, port))
        s.close()
        if res == 0:
            return True
    except Exception:
        pass

    if host in ("127.0.0.1", "0.0.0.0", "localhost"):
        try:
            import asyncio
            from amqtt.broker import Broker
            config = {
                'listeners': {'default': {'type': 'tcp', 'bind': f'{host}:{port}'}},
                'plugins': {'amqtt.plugins.authentication.AnonymousAuthPlugin': {'allow_anonymous': True}}
            }
            async def _run_b():
                b = Broker(config)
                await b.start()
                while True:
                    await asyncio.sleep(3600)
            def _b_thread():
                asyncio.run(_run_b())
            threading.Thread(target=_b_thread, daemon=True).start()
            time.sleep(1.2)
            print(f"[+] [Auto-Broker] Automatically launched embedded MQTT mesh broker on {host}:{port}", flush=True)
            return True
        except Exception as e:
            print(f"[!] [Auto-Broker] Could not auto-start embedded broker: {e}", flush=True)
    return False


def create_mqtt_client(client_id: str):
    try:
        from paho.mqtt.enums import CallbackAPIVersion
        return mqtt.Client(CallbackAPIVersion.VERSION2, client_id=client_id)
    except (ImportError, AttributeError):
        return mqtt.Client(client_id=client_id)


from mavlink_interface import MavlinkInterface

class DecentralizedSwarmNode:
    def __init__(self,
                 node_id: str,
                 local_broker_host: str = "127.0.0.1",
                 local_broker_port: int = 1883,
                 peer_brokers: Optional[List[str]] = None,
                 role: str = "primary",
                 frequency_hz: float = 3.0,
                 mission_duration_sec: float = 300.0,
                 mavlink_connection: Optional[str] = None,
                 mavlink_baud: int = 57600,
                 log_callback: Optional[Any] = None,
                 battery_voltage: Optional[float] = None,
                 health_score: float = 0.98,
                 gps_strength: float = 0.95,
                 gps_sats: int = 14,
                 gps_hdop: float = 0.8,
                 force_arm: bool = False,
                 auto_takeoff: bool = True,
                 takeoff_alt: float = 5.0,
                 acceptance_radius_m: float = 2.0,
                 speed_m_s: float = 3.0):
        self.node_id = node_id
        self.role = role.lower()  # "primary" or "backup"
        self.local_broker_host = local_broker_host
        self.local_broker_port = local_broker_port
        self.peer_endpoints: List[Tuple[str, int]] = self._parse_peer_endpoints(peer_brokers, default_port=local_broker_port)
        self.peer_broker_ips = [ep[0] for ep in self.peer_endpoints]
        self.frequency_hz = frequency_hz
        self.interval = 1.0 / frequency_hz
        self.duration_sec = mission_duration_sec
        self.log_callback = log_callback
        self.force_arm = force_arm
        self.auto_takeoff = auto_takeoff
        self.takeoff_alt = takeoff_alt
        self.acceptance_radius_m = acceptance_radius_m
        self.speed_m_s = speed_m_s
        self._last_wp_cmd_time = 0.0
        self._hardware_flight_active = False

        # Real Hardware MAVLink Interface (Direct to Cube Orange or SimVehicle)
        self.mavlink = MavlinkInterface(
            connection_string=mavlink_connection,
            baudrate=mavlink_baud,
            force_arm=force_arm,
            default_lat=WAYPOINT_COORDS[0]["lat"],
            default_lon=WAYPOINT_COORDS[0]["lon"]
        )

        # Security Subsystems
        self.protocol = DecentralizedProtocolEngine()
        self.trust_mgr = PeerTrustManager()
        self.controller = SwarmAdaptiveController(self.trust_mgr)
        self.ids = PeerIDSEngine()
        self.energy_mgr = EnergyManager()
        self.session_mgr = SessionTicketManager()

        # Multi-Criteria Optimal Backup Selector
        self.health_score = health_score
        self.gps_strength = gps_strength
        self.gps_sats = gps_sats
        self.gps_hdop = gps_hdop
        self.backup_selector = OptimalBackupSelector()
        self.backup_pool_candidates: Dict[str, BackupCandidateState] = {}
        self.known_peers = set(["drone_1", "drone_2", "drone_3", "backup_drone"])

        # Cryptographic Peer States: {peer_id: {"session_key": bytes, "kyber_param": int, "established": bool}}
        self.peer_sessions: Dict[str, Dict[str, Any]] = {}
        self.handshake_in_flight: Dict[str, Dict[str, Any]] = {}
        self.crypto_lock = threading.Lock()

        # Telemetry State: Start on ground at alt 0.0
        self.seq_num = 0
        self.current_wp_idx = 0
        self.lat = WAYPOINT_COORDS[0]["lat"]
        self.lon = WAYPOINT_COORDS[0]["lon"]
        self.alt = 0.0
        self.battery_voltage = battery_voltage if battery_voltage is not None else (11.52 if self.role == "primary" else 12.45)
        self.battery_cutoff = 10.20
        self.status = "STANDBY" if self.role == "backup" else "GROUND"

        # Backup Drone Takeover Tracking & Fault Location Navigation
        self.active_backup_target: Optional[str] = None
        self.last_primary_heartbeats: Dict[str, float] = {}
        self.peer_last_telemetry: Dict[str, Dict[str, Any]] = {}
        self.fault_target_pos: Optional[Dict[str, float]] = None
        self.heartbeat_timeout_sec = 10.0

        # MQTT Clients
        self.clients: List[mqtt.Client] = []
        self.running = False

    def log(self, msg: str, tag: str = "INFO"):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        prefix = f"[{self.node_id.upper()}]"
        formatted = f"[{ts}] {prefix} {msg}"
        with PRINT_LOCK:
            try:
                print(formatted, flush=True)
            except UnicodeEncodeError:
                try:
                    enc = sys.stdout.encoding or 'utf-8'
                    safe_msg = formatted.encode(enc, errors='replace').decode(enc)
                    print(safe_msg, flush=True)
                except Exception:
                    pass
            except Exception:
                pass
        if self.log_callback:
            try:
                self.log_callback(self.node_id, formatted, tag)
            except Exception:
                pass

    def start(self):
        self.running = True
        self.log(f"Starting Decentralized PQC UAV Node (Role: {self.role.upper()})", tag="INFO")

        # Verify or auto-start local MQTT broker if running on localhost
        ensure_local_broker(self.local_broker_host, self.local_broker_port)

        # Start MAVLink connection to Cube Orange / Telemetry Radio / SimVehicle
        self.mavlink.start()

        # If primary UAV and auto_takeoff, initiate preflight & takeoff
        if self.role == "primary" and self.auto_takeoff:
            threading.Thread(target=self._primary_takeoff_worker, daemon=True).start()

        # Connect to Local Broker
        c_local = self._init_mqtt_client(self.local_broker_host, self.local_broker_port, "local")
        self.clients.append(c_local)

        # Connect to Remote Peer Brokers
        for peer_host, peer_port in self.peer_endpoints:
            if peer_host and (peer_host != self.local_broker_host or peer_port != self.local_broker_port):
                clean_label = f"peer_{peer_host}_{peer_port}".replace(".", "_").replace(":", "_")
                c_peer = self._init_mqtt_client(peer_host, peer_port, clean_label)
                self.clients.append(c_peer)

        # Broadcast initial discovery / PQC handshake trigger
        threading.Thread(target=self._discovery_loop, daemon=True).start()

        # Start Telemetry Loop
        threading.Thread(target=self._telemetry_loop, daemon=True).start()

        # If Backup Drone, start Autonomous Failover Monitor (Eq. 4)
        if self.role == "backup":
            threading.Thread(target=self._backup_takeover_monitor, daemon=True).start()

        # Start Battery & Energy Monitor
        threading.Thread(target=self._energy_monitor_loop, daemon=True).start()

    def stop(self):
        self.running = False
        self.mavlink.stop()
        for c in self.clients:
            try:
                c.loop_stop()
                c.disconnect()
            except Exception:
                pass
        self.log("Node stopped.", tag="INFO")

    def _primary_takeoff_worker(self):
        """Pre-flight GPS check, mode switch, arming, takeoff, and climb verification for hardware or simulation."""
        self.status = "TAKEOFF"
        self.log(f"Preparing for Autonomous Takeoff (Target Alt={self.takeoff_alt:.1f}m, Speed={self.speed_m_s:.1f}m/s)...", tag="NAV")
        time.sleep(1.5)

        # Step 1: Pre-flight GPS verification for physical hardware
        if self.mavlink.is_connected:
            self.log("[MAVLink Hardware] Waiting for 3D GPS fix (min 6 satellites) on Cube Orange...", tag="NAV")
            gps_ok = self.mavlink.wait_for_gps(timeout=45.0, min_sats=6)
            if not gps_ok and not self.force_arm:
                self.log("[MAVLink Hardware] GPS fix timed out. Autonomous takeoff aborted to ensure safety. (Add --force-arm for indoor bench testing).", tag="ALERT")
                self.status = "GROUND"
                return

        # Step 2: Issue arm and takeoff command
        self.log(f"Arming motors and commanding takeoff to {self.takeoff_alt:.1f}m...", tag="NAV")
        if self.mavlink.command_arm_and_takeoff(target_alt_m=self.takeoff_alt, force=self.force_arm):
            # Step 3: Monitor climb progress until vehicle is airborne at target altitude
            self.log(f"Holding waypoint navigation until takeoff climb completes...", tag="NAV")
            self.mavlink.wait_for_takeoff_climb(target_alt_m=self.takeoff_alt, timeout=30.0)

            self.status = "FLYING"
            self.mavlink.set_speed(self.speed_m_s)
            self._hardware_flight_active = True
            target_wp = WAYPOINT_COORDS[self.current_wp_idx]
            self.mavlink.command_guided_waypoint(target_wp["lat"], target_wp["lon"], target_wp.get("alt", self.takeoff_alt))
            self.log(f"TAKEOFF COMPLETE! Motors armed & airborne at {self.alt:.1f}m. Navigating to Waypoint #1 ({target_wp['lat']:.6f}, {target_wp['lon']:.6f})...", tag="SUCCESS")
        else:
            self.log("Takeoff was rejected by Flight Controller. Check FCU diagnostics above.", tag="ALERT")
            self.status = "GROUND"

    # ─────────────────────────────────────────────────────────────
    # MQTT Mesh Networking
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_peer_endpoints(peer_entries: Optional[List[str]], default_port: int = 1883) -> List[Tuple[str, int]]:
        """Parses peer broker entries supporting comma-separated, space-separated, and host:port syntax."""
        endpoints = []
        if not peer_entries:
            return endpoints
        for item in peer_entries:
            if not item:
                continue
            parts = [p.strip() for p in str(item).split(",") if p.strip()]
            for p in parts:
                if ":" in p:
                    host_part, port_str = p.split(":", 1)
                    try:
                        port_val = int(port_str)
                    except ValueError:
                        port_val = default_port
                    endpoints.append((host_part.strip(), port_val))
                else:
                    endpoints.append((p.strip(), default_port))
        return endpoints

    def _init_mqtt_client(self, host: str, port: int, label: str) -> mqtt.Client:
        cid = f"{self.node_id}_{label}_{int(time.time()*1000)%100000}"
        client = create_mqtt_client(cid)

        def on_connect(c, userdata, flags, rc, properties=None):
            if rc == 0 or getattr(rc, "is_failure", None) is False:
                self.log(f"Connected to MQTT broker {host}:{port}", tag="SUCCESS")
                # Subscribe to discovery, handshake & alert channels
                c.subscribe("swarm/discovery", qos=1)
                c.subscribe(f"swarm/pqc/{self.node_id}/handshake_init", qos=1)
                c.subscribe(f"swarm/pqc/{self.node_id}/handshake_resp", qos=1)
                c.subscribe("swarm/alerts", qos=1)
                c.subscribe(f"swarm/cmd/{self.node_id}", qos=1)
                c.subscribe("swarm/cmd/all", qos=1)
                c.subscribe("drone/backup_trigger", qos=1)

                # Subscribe to individual active peer telemetry topics and dynamic discovery
                c.subscribe("swarm/pqc/+/telemetry", qos=1)
                for p in list(self.known_peers):
                    if p != self.node_id and not self.controller.is_isolated(p):
                        c.subscribe(f"swarm/pqc/{p}/telemetry", qos=1)

                # Broadcast immediate discovery beacon on newly connected broker
                beacon = {
                    "node_id": self.node_id,
                    "role": self.role,
                    "status": self.status,
                    "lat": self.lat,
                    "lon": self.lon,
                    "alt": self.alt,
                    "voltage": self.battery_voltage,
                    "timestamp": time.time()
                }
                c.publish("swarm/discovery", json.dumps(beacon), qos=1)
            else:
                self.log(f"Failed to connect to broker {host}:{port} (rc={rc})", tag="WARN")

        def on_message(c, userdata, msg):
            threading.Thread(target=self._handle_incoming_message, args=(msg.topic, msg.payload), daemon=True).start()

        client.on_connect = on_connect
        client.on_message = on_message

        try:
            client.connect_async(host, port, keepalive=60)
            client.loop_start()
        except Exception as e:
            self.log(f"Could not connect to {host}:{port}: {e}", tag="WARN")

        return client

    def _unsubscribe_peer(self, peer_id: str):
        """Unsubscribes from peer MQTT telemetry to completely ignore data from quarantined node."""
        for c in self.clients:
            try:
                c.unsubscribe(f"swarm/pqc/{peer_id}/telemetry")
            except Exception:
                pass

    def _subscribe_peer(self, peer_id: str):
        """Re-subscribes to peer MQTT telemetry when unquarantined / rekeyed."""
        for c in self.clients:
            try:
                c.subscribe(f"swarm/pqc/{peer_id}/telemetry", qos=1)
            except Exception:
                pass

    def quarantine_peer(self, peer_id: str, reason: str = "AI IDS Security Policy"):
        """Quarantines peer: deletes session keys, unsubscribes MQTT topics, and blocks communication."""
        self.controller.peer_isolated[peer_id] = True
        self.controller.peer_kyber_levels[peer_id] = 512
        self._unsubscribe_peer(peer_id)
        with self.crypto_lock:
            self.peer_sessions.pop(peer_id, None)
            self.handshake_in_flight.pop(peer_id, None)
        self.log(f"QUARANTINE [ISOLATED {peer_id.upper()}]: Keys revoked & MQTT unsubscribed. ({reason})", tag="ALERT")

    def _publish_mesh(self, topic: str, payload_str: str, qos: int = 0):
        for c in self.clients:
            try:
                c.publish(topic, payload_str, qos=qos)
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────
    # Mutual Hybrid Post-Quantum Handshake Engine
    # ─────────────────────────────────────────────────────────────

    def initiate_pqc_handshake(self, peer_id: str, kyber_level: Optional[int] = None):
        """Initiates mutual ECDH + Kyber handshake with a target peer."""
        if peer_id == self.node_id:
            return
        if self.controller.is_isolated(peer_id):
            self.log(f"Suppressed handshake initiation to isolated rogue peer: {peer_id}", tag="WARN")
            return

        with self.crypto_lock:
            # If active session already exists and no higher-tier rekey is requested, skip
            existing = self.peer_sessions.get(peer_id)
            if existing and (kyber_level is None or kyber_level == existing.get("kyber_param")):
                return
            if peer_id in self.handshake_in_flight:
                in_flight_age = time.perf_counter() - self.handshake_in_flight[peer_id].get("init_time", 0)
                if in_flight_age < 3.0:
                    return  # Handshake already actively in progress
                # Expired after 3.0s, allow re-initiating

        level = kyber_level or self.controller.get_kyber_level(peer_id)
        t0 = time.perf_counter()

        # 1. Generate ephemeral ECDH keypair (SECP256R1)
        ecc_priv = generate_private_key()
        ecc_pub = get_public_key(ecc_priv)
        ecc_pub_bytes = ecc_pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        # 2. Generate Kyber keypair
        kyber_pk, kyber_sk = generate_kyber_keypair(level)

        with self.crypto_lock:
            self.handshake_in_flight[peer_id] = {
                "ecc_priv": ecc_priv,
                "kyber_sk": kyber_sk,
                "kyber_param": level,
                "init_time": t0
            }

        payload = {
            "initiator_id": self.node_id,
            "target_id": peer_id,
            "kyber_level": level,
            "ecc_pub_hex": ecc_pub_bytes.hex(),
            "kyber_pk_hex": kyber_pk.hex()
        }

        packet = SwarmPacket(
            msg_type=MessageType.PQC_HANDSHAKE_INIT,
            sender_id=self.node_id,
            payload=payload,
            sequence_num=self.seq_num
        )
        self.seq_num += 1

        topic = f"swarm/pqc/{peer_id}/handshake_init"
        self._publish_mesh(topic, packet.serialize())
        self.log(f"Sent PQC_HANDSHAKE_INIT to {peer_id} (ML-KEM-{level} + ECC-P256)", tag="PQC")

    def _handle_handshake_init(self, packet: SwarmPacket):
        """Responder handles PQC_HANDSHAKE_INIT: encapsulates and returns response."""
        p = packet.payload
        peer_id = p["initiator_id"]
        target = p["target_id"]

        # Only process if this packet is meant for us or broadcast
        if target != self.node_id and target != "all":
            return
        if peer_id == self.node_id:
            return
        if self.controller.is_isolated(peer_id):
            self.log(f"Rejected handshake from quarantined rogue peer: {peer_id}", tag="WARN")
            return

        # Canonical tie-breaker for simultaneous dual-initiation:
        # If both nodes initiated to each other, the node with lower ID has priority,
        # UNLESS our initiation timed out (> 2.0s without reply), in which case accept peer's init.
        with self.crypto_lock:
            if peer_id in self.handshake_in_flight:
                in_flight_age = time.perf_counter() - self.handshake_in_flight[peer_id].get("init_time", 0)
                if in_flight_age > 2.0:
                    self.handshake_in_flight.pop(peer_id, None)
                elif self.node_id < peer_id:
                    # Fresh collision (<2.0s): lower ID has priority
                    return
                else:
                    # Peer has priority; discard our in-flight init and respond to peer
                    self.handshake_in_flight.pop(peer_id, None)

            # If established session already exists at this level, do not recreate
            existing = self.peer_sessions.get(peer_id)
            if existing and existing.get("kyber_param") == p["kyber_level"]:
                return

        level = p["kyber_level"]
        peer_ecc_bytes = bytes.fromhex(p["ecc_pub_hex"])
        peer_kyber_pk = bytes.fromhex(p["kyber_pk_hex"])

        t0 = time.perf_counter()

        # Step 1: Responder generates its ECDH keypair and computes shared secret
        my_ecc_priv = generate_private_key()
        my_ecc_pub = get_public_key(my_ecc_priv)
        my_ecc_pub_bytes = my_ecc_pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        peer_ecc_pub = ec.EllipticCurvePublicKey.from_encoded_point(my_ecc_pub.curve, peer_ecc_bytes)
        ecc_shared = get_shared_key(my_ecc_priv, peer_ecc_pub)

        # Step 2: Responder encapsulates with peer's Kyber public key
        ciphertext, kyber_shared = encapsulate_kyber(peer_kyber_pk, level)

        # Step 3: Combine secrets with live trust-driven alpha
        trust = self.trust_mgr.get_trust(peer_id)
        alpha = trust_to_alpha(trust)
        session_key, hkdf_ms = combine_secrets(ecc_shared, kyber_shared, alpha)

        tot_lat = (time.perf_counter() - t0) * 1000.0

        with self.crypto_lock:
            self.peer_sessions[peer_id] = {
                "session_key": session_key,
                "kyber_param": level,
                "established_at": time.time(),
                "alpha": alpha
            }
        self.controller.peer_kyber_levels[peer_id] = level
        self.protocol.reset_peer(peer_id)
        self.known_peers.add(peer_id)

        # Step 4: Issue a 0-RTT Session Resumption Ticket
        ticket_bytes = self.session_mgr.issue(peer_id, session_key, trust_score=trust)

        resp_payload = {
            "responder_id": self.node_id,
            "target_id": peer_id,
            "kyber_level": level,
            "ecc_pub_hex": my_ecc_pub_bytes.hex(),
            "kyber_ct_hex": ciphertext.hex(),
            "ticket_hex": ticket_bytes.hex(),
            "alpha": alpha
        }

        resp_packet = SwarmPacket(
            msg_type=MessageType.PQC_HANDSHAKE_RESP,
            sender_id=self.node_id,
            payload=resp_payload,
            sequence_num=self.seq_num
        )
        self.seq_num += 1

        topic = f"swarm/pqc/{peer_id}/handshake_resp"
        self._publish_mesh(topic, resp_packet.serialize())
        self.log(f"Completed PQC Handshake with {peer_id} (ML-KEM-{level}, alpha={alpha:.2f}, latency={tot_lat:.1f}ms)", tag="PQC")

    def _handle_handshake_resp(self, packet: SwarmPacket):
        """Initiator processes PQC_HANDSHAKE_RESP: decapsulates and finalizes session key."""
        p = packet.payload
        peer_id = p["responder_id"]
        if p["target_id"] != self.node_id:
            return

        with self.crypto_lock:
            if peer_id not in self.handshake_in_flight:
                return
            state = self.handshake_in_flight.pop(peer_id)

        level = p["kyber_level"]
        alpha = p.get("alpha", 0.5)
        resp_ecc_bytes = bytes.fromhex(p["ecc_pub_hex"])
        ciphertext = bytes.fromhex(p["kyber_ct_hex"])

        # Compute ECDH secret
        resp_ecc_pub = ec.EllipticCurvePublicKey.from_encoded_point(
            get_public_key(state["ecc_priv"]).curve, resp_ecc_bytes)
        ecc_shared = get_shared_key(state["ecc_priv"], resp_ecc_pub)

        # Decapsulate Kyber ciphertext
        kyber_shared = decapsulate_kyber(ciphertext, state["kyber_sk"], level)

        # Combine secrets
        session_key, hkdf_ms = combine_secrets(ecc_shared, kyber_shared, alpha)
        tot_lat = (time.perf_counter() - state["init_time"]) * 1000.0

        with self.crypto_lock:
            self.peer_sessions[peer_id] = {
                "session_key": session_key,
                "kyber_param": level,
                "established_at": time.time(),
                "alpha": alpha
            }
        self.controller.peer_kyber_levels[peer_id] = level
        self.protocol.reset_peer(peer_id)
        self.known_peers.add(peer_id)

        self.log(f"PQC Mutual Handshake Finalized with {peer_id} (ML-KEM-{level}, Total RTT={tot_lat:.1f}ms)", tag="PQC")

    # ─────────────────────────────────────────────────────────────
    # Telemetry Broadcasting & Encrypted Message Handling
    # ─────────────────────────────────────────────────────────────

    def _telemetry_loop(self):
        start_time = time.time()
        tx_counter = 0
        while self.running and (time.time() - start_time) < self.duration_sec:
            t0 = time.time()

            # If standing by as backup, broadcast periodic candidate telemetry to mesh
            if self.role == "backup" and self.status == "STANDBY":
                standby_telem = {
                    "drone_id": self.node_id,
                    "role": "backup",
                    "lat": round(self.lat, 6),
                    "lon": round(self.lon, 6),
                    "alt": round(self.alt, 2),
                    "voltage": round(self.battery_voltage, 3),
                    "health": round(self.health_score, 3),
                    "gps_strength": round(self.gps_strength, 3),
                    "gps_sats": self.gps_sats,
                    "gps_hdop": round(self.gps_hdop, 2),
                    "current": 0.0,
                    "status": "STANDBY",
                    "active_target": self.active_backup_target,
                    "seq": self.seq_num
                }
                disc_packet = SwarmPacket(
                    msg_type=MessageType.PQC_ENCRYPTED_TELEMETRY,
                    sender_id=self.node_id,
                    payload={"plain_discovery": standby_telem},
                    sequence_num=self.seq_num
                )
                self.seq_num += 1
                self._publish_mesh(f"swarm/pqc/{self.node_id}/telemetry", disc_packet.serialize())

                # Also send encrypted if sessions established
                with self.crypto_lock:
                    peers_copy = list(self.peer_sessions.items())
                if peers_copy:
                    raw_standby = json.dumps(standby_telem).encode('utf-8')
                    for peer_id, p_info in peers_copy:
                        if self.controller.is_isolated(peer_id):
                            continue
                        cipher_bytes = encrypt_data(raw_standby, p_info["session_key"])
                        enc_payload = {
                            "target_peer": peer_id,
                            "kyber_level": p_info["kyber_param"],
                            "cipher_hex": cipher_bytes.hex()
                        }
                        packet = SwarmPacket(
                            msg_type=MessageType.PQC_ENCRYPTED_TELEMETRY,
                            sender_id=self.node_id,
                            payload=enc_payload,
                            sequence_num=self.seq_num
                        )
                        self.seq_num += 1
                        self._publish_mesh(f"swarm/pqc/{self.node_id}/telemetry", packet.serialize())
                time.sleep(1.0)
                continue

            # Update coordinates (gradually advance along waypoints)
            self._update_kinematics()

            telem_payload = {
                "drone_id": self.node_id,
                "role": self.role,
                "lat": round(self.lat, 6),
                "lon": round(self.lon, 6),
                "alt": round(self.alt, 2),
                "voltage": round(self.battery_voltage, 3),
                "health": round(self.health_score, 3),
                "gps_strength": round(self.gps_strength, 3),
                "gps_sats": self.gps_sats,
                "gps_hdop": round(self.gps_hdop, 2),
                "current": -0.01,
                "status": self.status,
                "active_target": self.active_backup_target,
                "seq": self.seq_num
            }

            raw_bytes = json.dumps(telem_payload).encode('utf-8')

            # Broadcast encrypted copy for each active peer session
            with self.crypto_lock:
                peers_copy = list(self.peer_sessions.items())

            if not peers_copy:
                # If no PQC peer established yet, send plain discovery frame to prompt handshake
                disc_packet = SwarmPacket(
                    msg_type=MessageType.PQC_ENCRYPTED_TELEMETRY,
                    sender_id=self.node_id,
                    payload={"plain_discovery": telem_payload},
                    sequence_num=self.seq_num
                )
                self.seq_num += 1
                self._publish_mesh(f"swarm/pqc/{self.node_id}/telemetry", disc_packet.serialize())
            else:
                for peer_id, p_info in peers_copy:
                    if self.controller.is_isolated(peer_id):
                        continue
                    key = p_info["session_key"]
                    level = p_info["kyber_param"]
                    cipher_bytes = encrypt_data(raw_bytes, key)

                    enc_payload = {
                        "target_peer": peer_id,
                        "kyber_level": level,
                        "cipher_hex": cipher_bytes.hex()
                    }

                    packet = SwarmPacket(
                        msg_type=MessageType.PQC_ENCRYPTED_TELEMETRY,
                        sender_id=self.node_id,
                        payload=enc_payload,
                        sequence_num=self.seq_num
                    )
                    self.seq_num += 1
                    self._publish_mesh(f"swarm/pqc/{self.node_id}/telemetry", packet.serialize())

            tx_counter += 1
            if tx_counter % max(1, int(self.frequency_hz)) == 0:
                self.log(f"TX TELEMETRY: WP#{self.current_wp_idx+1} Lat={self.lat:.6f}, Lon={self.lon:.6f}, Alt={self.alt:.1f}m, Bat={self.battery_voltage:.2f}V, Status={self.status}", tag="TELEM")

            # Maintain precision telemetry interval
            elapsed = time.time() - t0
            time.sleep(max(0.0, self.interval - elapsed))

    def trigger_emergency_land_and_backup(self, reason: str = "Operator 'b' emergency backup trigger"):
        """Initiates immediate on-site landing for this drone and broadcasts node failure to summon Backup Drone."""
        self.status = "LANDING"
        self.log(f"EMERGENCY LANDING TRIGGERED: Initiating on-site descent at Lat={self.lat:.6f}, Lon={self.lon:.6f}, Alt={self.alt:.1f}m. Summoning Backup Drone! ({reason})", tag="TAKEOVER")

        # Command real Cube Orange hardware to LAND immediately on site
        self.mavlink.command_emergency_land()

        alert_payload = {
            "failed_id": self.node_id,
            "last_lat": self.lat,
            "last_lon": self.lon,
            "last_alt": self.alt,
            "waypoint_idx": self.current_wp_idx,
            "timestamp": time.time(),
            "reason": reason
        }
        pkt = SwarmPacket(
            msg_type=MessageType.ALERT_NODE_FAILURE,
            sender_id=self.node_id,
            payload=alert_payload,
            sequence_num=self.seq_num
        )
        self.seq_num += 1
        self._publish_mesh("swarm/alerts", pkt.serialize())

    def _update_kinematics(self):
        # Synchronize telemetry snapshot from MAVLink interface (hardware or simulation)
        snap = self.mavlink.get_telemetry_snapshot()
        self.lat = snap["lat"]
        self.lon = snap["lon"]
        self.alt = snap["alt"]
        self.battery_voltage = snap["voltage"]
        self.gps_sats = snap.get("sats", self.gps_sats)
        if self.gps_sats > 0:
            self.gps_strength = min(1.0, max(0.5, self.gps_sats / 15.0))

        if self.status == "LANDING":
            if not snap.get("armed", False) or self.alt <= 0.05:
                self.status = "LANDED"
                self.alt = 0.0
                self.log(f"TOUCHDOWN CONFIRMED: Drone {self.node_id.upper()} safely LANDED and disarmed.", tag="SUCCESS")
            return
        elif self.status in ("LANDED", "STANDBY", "GROUND", "TAKEOFF"):
            return

        # Backup drone: Fly DIRECTLY to the fault drone's coordinates and immediately LAND on arrival (no other waypoints)
        if self.status == "ACTIVE_BACKUP" and self.alt >= 1.0:
            if not self.fault_target_pos:
                self.fault_target_pos = {"lat": self.lat, "lon": self.lon, "alt": self.takeoff_alt}

            t_lat = self.fault_target_pos["lat"]
            t_lon = self.fault_target_pos["lon"]
            t_alt = self.fault_target_pos.get("alt", self.takeoff_alt)
            dist = haversine_distance_m(self.lat, self.lon, t_lat, t_lon)

            now = time.time()
            if now - self._last_wp_cmd_time >= 1.0:
                self.mavlink.command_guided_waypoint(t_lat, t_lon, t_alt)
                self._last_wp_cmd_time = now
                target_name = self.active_backup_target.upper() if self.active_backup_target else "FAULT DRONE"
                self.log(f"BACKUP FLIGHT: Navigating to {target_name} -> Target=({t_lat:.6f}, {t_lon:.6f}) | Current=({self.lat:.6f}, {self.lon:.6f}) | Dist={dist:.1f}m | Alt={self.alt:.1f}m", tag="NAV")

            if dist <= self.acceptance_radius_m:
                target_name = self.active_backup_target.upper() if self.active_backup_target else "FAULT DRONE"
                self.log("=" * 65, tag="SUCCESS")
                self.log(f"ARRIVED AT FAULT POINT OF {target_name} (dist={dist:.2f}m <= {self.acceptance_radius_m:.1f}m)!", tag="SUCCESS")
                self.log(f"Executing autonomous LANDING at fault coordinates (Lat={self.lat:.6f}, Lon={self.lon:.6f})...", tag="SUCCESS")
                self.log("=" * 65, tag="SUCCESS")
                self.status = "LANDING"
                self.mavlink.command_emergency_land()
            return

        # Primary drone: Advance waypoints and stream GUIDED targets only when active in flight and airborne (alt >= 1.0m)
        elif self.status == "FLYING" and self.alt >= 1.0:
            target_wp = WAYPOINT_COORDS[self.current_wp_idx]
            dist = haversine_distance_m(self.lat, self.lon, target_wp["lat"], target_wp["lon"])

            now = time.time()
            if now - self._last_wp_cmd_time >= 1.0:
                self.mavlink.command_guided_waypoint(
                    target_wp["lat"], target_wp["lon"], target_wp.get("alt", self.takeoff_alt)
                )
                self._last_wp_cmd_time = now

            if dist <= self.acceptance_radius_m:
                self.log(f"REACHED WAYPOINT #{self.current_wp_idx + 1} (dist={dist:.2f}m <= {self.acceptance_radius_m:.1f}m).", tag="SUCCESS")
                if self.current_wp_idx < len(WAYPOINT_COORDS) - 1:
                    self.current_wp_idx += 1
                    next_wp = WAYPOINT_COORDS[self.current_wp_idx]
                    self.log(f"Advancing to Waypoint #{self.current_wp_idx + 1} (Lat={next_wp['lat']:.6f}, Lon={next_wp['lon']:.6f}).", tag="NAV")
                    self.mavlink.command_guided_waypoint(
                        next_wp["lat"], next_wp["lon"], next_wp.get("alt", self.takeoff_alt)
                    )
                else:
                    self.log("ALL WAYPOINTS COMPLETED: Executing final landing on site...", tag="SUCCESS")
                    self.status = "LANDING"
                    self.mavlink.command_emergency_land()

        # Gradual battery decay
        self.battery_voltage = max(self.battery_cutoff - 0.1, self.battery_voltage - 0.0003)

    def _handle_incoming_message(self, topic: str, raw_bytes: bytes):
        try:
            raw_str = raw_bytes.decode('utf-8')
        except Exception:
            return

        # Check for dynamic swarm discovery announcements
        if topic == "swarm/discovery":
            try:
                d_info = json.loads(raw_str)
                sender = d_info.get("node_id")
                if sender and sender != self.node_id:
                    self.known_peers.add(sender)
                    self.last_primary_heartbeats[sender] = time.time()
                    if "lat" in d_info and "lon" in d_info:
                        self.peer_last_telemetry[sender] = {
                            "lat": float(d_info["lat"]),
                            "lon": float(d_info["lon"]),
                            "alt": float(d_info.get("alt", self.takeoff_alt)),
                            "timestamp": time.time()
                        }
                    if d_info.get("role") == "backup" or "backup" in sender.lower() or d_info.get("status") == "STANDBY":
                        self.backup_pool_candidates[sender] = BackupCandidateState(
                            node_id=sender,
                            lat=d_info.get("lat", self.lat),
                            lon=d_info.get("lon", self.lon),
                            alt=d_info.get("alt", self.alt),
                            voltage=d_info.get("voltage", 12.0),
                            health_score=d_info.get("health", 0.98),
                            gps_strength=d_info.get("gps_strength", 0.95),
                            gps_sats=d_info.get("gps_sats", 14),
                            gps_hdop=d_info.get("gps_hdop", 0.8),
                            trust_score=self.trust_mgr.get_trust(sender),
                            status=d_info.get("status", "STANDBY"),
                            is_isolated=self.controller.is_isolated(sender),
                            last_seen=time.time()
                        )
                    # Trigger mutual handshake if not yet established
                    if sender not in self.peer_sessions and sender not in self.handshake_in_flight and not self.controller.is_isolated(sender):
                        self.initiate_pqc_handshake(sender)
            except Exception:
                pass
            return

        # Check for remote operator CLI/GUI commands
        if topic.startswith("swarm/cmd/"):
            self._handle_remote_command(raw_str)
            return

        # Check for IEEE backup triggers
        if topic == "drone/backup_trigger" and self.role == "backup" and self.status != "ACTIVE_BACKUP":
            try:
                b_data = json.loads(raw_str)
                target = b_data.get("drone_id", "drone_1")
                last_telem = self.peer_last_telemetry.get(target, {})
                t_lat = b_data.get("lat") or last_telem.get("lat") or self.lat
                t_lon = b_data.get("lon") or last_telem.get("lon") or self.lon
                t_alt = b_data.get("alt") or last_telem.get("alt") or self.takeoff_alt
                self._evaluate_and_execute_optimal_takeover(
                    failed_id=target,
                    reason="External Operator Backup Trigger",
                    target_lat=float(t_lat),
                    target_lon=float(t_lon),
                    target_alt=float(t_alt),
                    wp_idx=b_data.get("waypoint_idx", self.current_wp_idx)
                )
            except Exception:
                pass
            return

        packet = SwarmPacket.deserialize(raw_str)
        if not packet:
            return

        sender = packet.sender_id
        if sender == self.node_id:
            return  # Ignore self messages

        # Drop and ignore all data from quarantined peers (no processing, no reading)
        if self.controller.is_isolated(sender):
            return

        # Check anti-replay, mesh deduplication, and freshness
        valid, reason = self.protocol.validate_packet(packet)
        if not valid:
            if "DUPLICATE" in reason.upper() or "MULTIPATH" in reason.upper():
                # Redundant mesh path delivery: benign duplicate, silently ignore!
                return
            elif "SKEW" in reason.upper():
                self.log(f"Clock skew detected from {sender}: {reason}", tag="WARN")
                return
            else:
                self.log(f"DROPPED PACKET from {sender}: {reason}", tag="ALERT")
                # Apply security penalty and trigger escalation ladder for true replay attack
                ids_result = {
                    "threat_prob": 0.88,
                    "is_anomaly": True,
                    "conformal_set": "{Intruder}",
                    "anomaly_reasons": [reason]
                }
                self._apply_security_decision(sender, ids_result)
                return

        # Update heartbeat for failover monitor
        self.last_primary_heartbeats[sender] = time.time()
        self.known_peers.add(sender)

        # Route by message type
        mtype = packet.msg_type
        if mtype == MessageType.PQC_HANDSHAKE_INIT.value:
            self._handle_handshake_init(packet)
        elif mtype == MessageType.PQC_HANDSHAKE_RESP.value:
            self._handle_handshake_resp(packet)
        elif mtype == MessageType.PQC_ENCRYPTED_TELEMETRY.value:
            self._handle_encrypted_telemetry(packet)
        elif mtype == MessageType.ALERT_ROGUE_ISOLATED.value:
            self._handle_rogue_alert(packet)
        elif mtype == MessageType.ALERT_NODE_FAILURE.value:
            self._handle_node_failure(packet)

    def _handle_encrypted_telemetry(self, packet: SwarmPacket):
        sender = packet.sender_id
        payload = packet.payload

        # Handle plain discovery frame (trigger PQC handshake or evaluate spoof injection)
        if "plain_discovery" in payload:
            disc_telem = payload["plain_discovery"]
            if isinstance(disc_telem, dict):
                if "lat" in disc_telem and "lon" in disc_telem:
                    self.peer_last_telemetry[sender] = {
                        "lat": float(disc_telem["lat"]),
                        "lon": float(disc_telem["lon"]),
                        "alt": float(disc_telem.get("alt", self.takeoff_alt)),
                        "timestamp": time.time()
                    }
                    # Evaluate telemetry for anomalies (e.g. spoofing)
                    ids_result = self.ids.evaluate_peer_telemetry(sender, disc_telem, raw_packet_size=128)
                    self._apply_security_decision(sender, ids_result)

                # Record candidate state in backup pool if candidate is backup/standby
                if disc_telem.get("role") == "backup" or "backup" in sender.lower() or disc_telem.get("status") == "STANDBY":
                    self.backup_pool_candidates[sender] = BackupCandidateState(
                        node_id=sender,
                        lat=disc_telem.get("lat", self.lat),
                        lon=disc_telem.get("lon", self.lon),
                        alt=disc_telem.get("alt", self.alt),
                        voltage=disc_telem.get("voltage", 12.0),
                        health_score=disc_telem.get("health", 0.98),
                        gps_strength=disc_telem.get("gps_strength", 0.95),
                        gps_sats=disc_telem.get("gps_sats", 14),
                        gps_hdop=disc_telem.get("gps_hdop", 0.8),
                        trust_score=self.trust_mgr.get_trust(sender),
                        status=disc_telem.get("status", "STANDBY"),
                        is_isolated=self.controller.is_isolated(sender),
                        last_seen=time.time()
                    )

            if sender not in self.peer_sessions and sender not in self.handshake_in_flight:
                if not self.controller.is_isolated(sender):
                    self.initiate_pqc_handshake(sender)
            return

        # Process encrypted frame targeted to this node
        target_peer = payload.get("target_peer")
        if target_peer and target_peer != self.node_id:
            return  # Encrypted for a different peer

        with self.crypto_lock:
            p_info = self.peer_sessions.get(sender)

        if not p_info:
            if not (sender.startswith("drone_") or sender.startswith("backup_drone")):
                self.log(f"SECURITY ACTION: Unauthorized peer '{sender}' connection REJECTED (Missing PQC Session Credentials). Packet DROPPED.", tag="ALERT")
                return
            # Need to establish PQC session first for valid peers
            if sender not in self.handshake_in_flight and not self.controller.is_isolated(sender):
                self.initiate_pqc_handshake(sender)
            return

        cipher_bytes = bytes.fromhex(payload["cipher_hex"])
        key = p_info["session_key"]
        plain_bytes = decrypt_data(cipher_bytes, key)

        if not plain_bytes:
            self.log(f"Decryption failed for packet from {sender}! Potential tampering/MITM.", tag="ALERT")
            ids_result = {
                "threat_prob": 0.88,
                "is_anomaly": True,
                "conformal_set": "{Intruder}",
                "anomaly_reasons": ["Ciphertext decryption failure / key mismatch"]
            }
            self._apply_security_decision(sender, ids_result)
            return

        try:
            telem = json.loads(plain_bytes.decode('utf-8'))
        except Exception:
            return

        if isinstance(telem, dict) and "lat" in telem and "lon" in telem:
            self.peer_last_telemetry[sender] = {
                "lat": float(telem["lat"]),
                "lon": float(telem["lon"]),
                "alt": float(telem.get("alt", self.takeoff_alt)),
                "timestamp": time.time()
            }

        # Record candidate state from decrypted stream if candidate is backup
        if telem.get("role") == "backup" or "backup" in sender.lower() or telem.get("status") == "STANDBY":
            self.backup_pool_candidates[sender] = BackupCandidateState(
                node_id=sender,
                lat=telem.get("lat", self.lat),
                lon=telem.get("lon", self.lon),
                alt=telem.get("alt", self.alt),
                voltage=telem.get("voltage", 12.0),
                health_score=telem.get("health", 0.98),
                gps_strength=telem.get("gps_strength", 0.95),
                gps_sats=telem.get("gps_sats", 14),
                gps_hdop=telem.get("gps_hdop", 0.8),
                trust_score=self.trust_mgr.get_trust(sender),
                status=telem.get("status", "STANDBY"),
                is_isolated=self.controller.is_isolated(sender),
                last_seen=time.time()
            )

        # Log incoming decrypted peer telemetry (READ DATA)
        pqc_lvl = p_info["kyber_param"]
        alpha_val = p_info.get("alpha", 0.0)
        self.log(
            f"RX DECRYPTED [{sender.upper()}]: Lat={telem.get('lat', 0):.6f}, Lon={telem.get('lon', 0):.6f}, Alt={telem.get('alt', 0):.1f}m, Bat={telem.get('voltage', 0):.2f}V, Status={telem.get('status', 'FLYING')} [ML-KEM-{pqc_lvl}, alpha={alpha_val:.2f}]",
            tag="RECV"
        )

        # ── LOCAL AI INTRUSION DETECTION & CONFORMAL RISK EVALUATION ──
        ids_result = self.ids.evaluate_peer_telemetry(sender, telem, raw_packet_size=len(cipher_bytes))
        self._apply_security_decision(sender, ids_result)

    def _apply_security_decision(self, sender: str, ids_result: Dict[str, Any]):
        """Evaluates peer against the adaptive security ladder, updates Kyber levels, and triggers rekeys."""
        sec_decision = self.controller.evaluate_peer(sender, ids_result)
        trust = sec_decision["trust"]
        c_set = ids_result.get("conformal_set", "{Normal}")
        prob = ids_result.get("threat_prob", 0.0)
        new_level = sec_decision["kyber_level"]
        prev_level = sec_decision["previous_level"]

        if ids_result.get("is_anomaly"):
            self.log(f"AI IDS ALERT from {sender}: {c_set} | Threat={prob:.2f} | Trust={trust:.2f} | Reasons={ids_result.get('anomaly_reasons')}", tag="ALERT")

        # Check for dynamic rekey requirement (Escalation or De-escalation!)
        if sec_decision["rekey_needed"] and not sec_decision["isolate_peer"]:
            shift_type = "Escalation" if new_level > prev_level else "De-escalation"
            self.log(f"Security Ladder Shift ({shift_type}) for {sender} -> ML-KEM-{new_level}: {sec_decision['reason']}", tag="WARN" if shift_type == "Escalation" else "PQC")
            self.initiate_pqc_handshake(sender, kyber_level=new_level)

        # Check for Rogue Node Quarantine
        if sec_decision["isolate_peer"]:
            self.quarantine_peer(sender, sec_decision["reason"])
            alert_payload = {
                "rogue_id": sender,
                "detected_by": self.node_id,
                "trust": trust,
                "threat_prob": prob,
                "conformal_set": c_set,
                "timestamp": time.time(),
                "reason": sec_decision["reason"]
            }
            alert_packet = SwarmPacket(
                msg_type=MessageType.ALERT_ROGUE_ISOLATED,
                sender_id=self.node_id,
                payload=alert_payload,
                sequence_num=self.seq_num
            )
            self.seq_num += 1
            self._publish_mesh("swarm/alerts", alert_packet.serialize())

    # ─────────────────────────────────────────────────────────────
    # Autonomous Backup Drone Mission Handover (Sajid et al. Eq. 4)
    # ─────────────────────────────────────────────────────────────

    def _evaluate_and_execute_optimal_takeover(self, failed_id: str, reason: str, target_lat: float, target_lon: float, target_alt: float = 5.0, wp_idx: Optional[int] = None):
        """
        Algorithm 1 (Enhanced): Evaluates all candidate backup UAVs in the swarm pool
        across 5 criteria: Battery Voltage, Present Health, GPS Strength, Waypoint Distance,
        and Peer Trust Score. Selects the globally optimal UAV B* to assume the mission.
        """
        if self.role != "backup" or self.status == "ACTIVE_BACKUP":
            return

        # Ensure local node's freshest state is registered in pool
        self.backup_pool_candidates[self.node_id] = BackupCandidateState(
            node_id=self.node_id,
            lat=self.lat,
            lon=self.lon,
            alt=self.alt,
            voltage=self.battery_voltage,
            health_score=self.health_score,
            gps_strength=self.gps_strength,
            gps_sats=self.gps_sats,
            gps_hdop=self.gps_hdop,
            trust_score=1.0,
            status=self.status,
            is_isolated=self.controller.is_isolated(self.node_id)
        )

        candidate_list = list(self.backup_pool_candidates.values())
        winner, report = self.backup_selector.select_optimal_backup(candidate_list, target_lat, target_lon)

        if not winner:
            self.log("OPTIMAL BACKUP SELECTION: No eligible candidate met safety/trust thresholds!", tag="WARN")
            return

        if winner.node_id == self.node_id:
            self.log("=" * 65, tag="TAKEOVER")
            self.log(f"*** OPTIMAL BACKUP UAV ELECTED: {self.node_id.upper()} CHOSEN AS BEST REPLACEMENT ***", tag="TAKEOVER")
            self.log(f"Composite Utility Score: {report['winner_score']:.4f} (Evaluated {report['total_candidates']} candidate backup drones)", tag="TAKEOVER")
            if report['rankings']:
                r0 = report['rankings'][0]
                self.log(f"Optimization Breakdown : Battery={r0['e_battery_norm']:.2f}, Health={r0['h_health_norm']:.2f}, GPS={r0['g_gps_norm']:.2f}, Dist={r0['d_dist_norm']:.2f}, Trust={r0['t_trust_norm']:.2f}", tag="TAKEOVER")
            self.log("=" * 65, tag="TAKEOVER")
            if wp_idx is not None:
                self.current_wp_idx = wp_idx
            self._trigger_backup_takeover(
                target_drone_id=failed_id,
                reason=reason,
                target_lat=target_lat,
                target_lon=target_lon,
                target_alt=target_alt,
                selection_report=report
            )
        else:
            self.log(f"OPTIMAL BACKUP SELECTION: Drone '{winner.node_id}' elected as optimal replacement (Score: {report['winner_score']:.4f}). This node remaining in STANDBY.", tag="TAKEOVER")

    def _backup_takeover_monitor(self):
        """Monitors primary drone heartbeats and triggers autonomous takeover on 10s loss."""
        while self.running:
            time.sleep(1.0)
            if self.role != "backup" or self.status == "ACTIVE_BACKUP":
                continue

            t_now = time.time()
            for primary_id, last_hb in list(self.last_primary_heartbeats.items()):
                loss_sec = t_now - last_hb
                if loss_sec >= self.heartbeat_timeout_sec:
                    self.log(f"TIMEOUT TRIGGER: Primary {primary_id} silent for {loss_sec:.1f}s (exceeds {self.heartbeat_timeout_sec}s cutoff)!", tag="TAKEOVER")
                    last_telem = self.peer_last_telemetry.get(primary_id, {})
                    target_lat = last_telem.get("lat") or self.lat
                    target_lon = last_telem.get("lon") or self.lon
                    target_alt = last_telem.get("alt") or self.takeoff_alt
                    self._evaluate_and_execute_optimal_takeover(
                        failed_id=primary_id,
                        reason=f"Silent node timeout ({loss_sec:.1f}s)",
                        target_lat=float(target_lat),
                        target_lon=float(target_lon),
                        target_alt=float(target_alt),
                        wp_idx=self.current_wp_idx
                    )
                    break

    def _handle_rogue_alert(self, packet: SwarmPacket):
        p = packet.payload
        rogue_id = p["rogue_id"]
        if rogue_id == self.node_id:
            return
        self.log(f"RECEIVED SWARM ALERT: Peer {rogue_id.upper()} isolated by {p['detected_by']} ({p['conformal_set']})", tag="ALERT")
        self.quarantine_peer(rogue_id, f"Swarm Alert from {p['detected_by']}")

        # If Backup Drone, evaluate optimal candidate to take over rogue drone's mission
        if self.role == "backup" and self.status != "ACTIVE_BACKUP":
            last_telem = self.peer_last_telemetry.get(rogue_id, {})
            target_lat = last_telem.get("lat") or self.lat
            target_lon = last_telem.get("lon") or self.lon
            target_alt = last_telem.get("alt") or self.takeoff_alt
            self._evaluate_and_execute_optimal_takeover(
                failed_id=rogue_id,
                reason=f"Primary node compromised and isolated by AI IDS ({p['conformal_set']})",
                target_lat=float(target_lat),
                target_lon=float(target_lon),
                target_alt=float(target_alt),
                wp_idx=self.current_wp_idx
            )

    def _handle_node_failure(self, packet: SwarmPacket):
        p = packet.payload
        failed_id = p.get("failed_id")
        if failed_id == self.node_id:
            return
        self.log(f"ALERT: Drone {failed_id.upper()} initiated on-site emergency landing. Evaluating optimal Backup Drone.", tag="TAKEOVER")
        if self.role == "backup" and self.status != "ACTIVE_BACKUP":
            last_telem = self.peer_last_telemetry.get(failed_id, {})
            target_lat = p.get("last_lat") or last_telem.get("lat") or self.lat
            target_lon = p.get("last_lon") or last_telem.get("lon") or self.lon
            target_alt = p.get("last_alt") or last_telem.get("alt") or self.takeoff_alt
            self._evaluate_and_execute_optimal_takeover(
                failed_id=failed_id,
                reason=f"On-site landing failover triggered by {failed_id} ('b' key)",
                target_lat=float(target_lat),
                target_lon=float(target_lon),
                target_alt=float(target_alt),
                wp_idx=p.get("waypoint_idx", self.current_wp_idx)
            )

    def _trigger_backup_takeover(self, target_drone_id: str, reason: str, target_lat: float, target_lon: float, target_alt: float = 5.0, selection_report: Optional[Dict[str, Any]] = None):
        self.status = "ACTIVE_BACKUP"
        self.active_backup_target = target_drone_id
        cruise_alt = max(float(target_alt), self.takeoff_alt)
        self.fault_target_pos = {
            "lat": float(target_lat),
            "lon": float(target_lon),
            "alt": cruise_alt
        }
        self.log("=" * 65, tag="TAKEOVER")
        self.log("*** AUTONOMOUS BACKUP MISSION TAKEOVER ACTIVATED ***", tag="TAKEOVER")
        self.log(f"Replacing Faulty Drone : {target_drone_id.upper()}", tag="TAKEOVER")
        self.log(f"Fault Drone Target Coords: Lat={target_lat:.6f}, Lon={target_lon:.6f}, Alt={cruise_alt:.1f}m", tag="TAKEOVER")
        self.log(f"Trigger Reason         : {reason}", tag="TAKEOVER")
        self.log(f"Mission Directive      : Direct flight to fault location -> Auto-LAND (Skipping pre-set waypoints)", tag="TAKEOVER")
        self.log("=" * 65, tag="TAKEOVER")

        # Command physical or simulated takeoff and flight towards target coordinates
        def _takeover_flight():
            self.log(f"Backup takeover: initializing takeoff sequence (target alt={self.takeoff_alt:.1f}m)...", tag="TAKEOVER")
            self.status = "TAKEOFF"
            time.sleep(1.0)
            if self.mavlink.is_connected:
                self.mavlink.wait_for_gps(timeout=30.0, min_sats=6)
            if self.mavlink.command_arm_and_takeoff(target_alt_m=self.takeoff_alt, force=self.force_arm):
                self.mavlink.wait_for_takeoff_climb(target_alt_m=self.takeoff_alt, timeout=30.0)
                self.status = "ACTIVE_BACKUP"
                self.mavlink.set_speed(self.speed_m_s)
                snap = self.mavlink.get_telemetry_snapshot()
                self.alt = snap.get("alt", self.takeoff_alt)
                self.mavlink.command_guided_waypoint(target_lat, target_lon, cruise_alt)
                self.log(f"Backup drone airborne at {self.alt:.1f}m! Navigating DIRECTLY to fault point of {target_drone_id.upper()} ({target_lat:.6f}, {target_lon:.6f})...", tag="SUCCESS")
            else:
                self.log("Backup takeover takeoff failed! Check FCU diagnostics.", tag="ALERT")
                self.status = "GROUND"

        threading.Thread(target=_takeover_flight, daemon=True).start()

        # Broadcast Takeover Alert
        alert_payload = {
            "backup_node": self.node_id,
            "target_node": target_drone_id,
            "target_lat": target_lat,
            "target_lon": target_lon,
            "timestamp": time.time(),
            "reason": reason,
            "selection_report": selection_report
        }
        pkt = SwarmPacket(
            msg_type=MessageType.ALERT_BACKUP_TAKEOVER,
            sender_id=self.node_id,
            payload=alert_payload,
            sequence_num=self.seq_num
        )
        self.seq_num += 1
        self._publish_mesh("swarm/alerts", pkt.serialize())

    # ─────────────────────────────────────────────────────────────
    # Energy Capping & Discovery Loops
    # ─────────────────────────────────────────────────────────────

    def _discovery_loop(self):
        """Periodically announces presence to establish mutual PQC mesh with all online peers."""
        while self.running:
            time.sleep(3.5)
            # Broadcast presence beacon on discovery channel
            beacon = {
                "node_id": self.node_id,
                "role": self.role,
                "status": self.status,
                "lat": self.lat,
                "lon": self.lon,
                "alt": self.alt,
                "voltage": self.battery_voltage,
                "timestamp": time.time()
            }
            self._publish_mesh("swarm/discovery", json.dumps(beacon), qos=1)

            # Probe any known peer IDs not yet established
            all_peers = set(list(self.known_peers) + list(self.backup_pool_candidates.keys()))
            for pid in all_peers:
                if pid != self.node_id and pid not in self.peer_sessions and not self.controller.is_isolated(pid):
                    if pid not in self.handshake_in_flight:
                        self.initiate_pqc_handshake(pid)

    def _energy_monitor_loop(self):
        """Monitors battery voltage; enforces energy-aware capping if battery drops below cutoff."""
        warned = False
        while self.running:
            time.sleep(5.0)
            if self.battery_voltage <= self.battery_cutoff:
                if not warned:
                    self.log(f"ENERGY GATE: Battery ({self.battery_voltage:.2f}V) below cutoff ({self.battery_cutoff:.2f}V). Capping PQC level to Kyber-512 to preserve flight endurance.", tag="WARN")
                    for pid in list(self.controller.peer_kyber_levels.keys()):
                        self.controller.peer_kyber_levels[pid] = 512
                    warned = True
            else:
                warned = False

    def _handle_remote_command(self, raw_str: str):
        try:
            data = json.loads(raw_str)
            cmd = data.get("cmd", "").strip().lower()
            self.log(f"REMOTE COMMAND: '{cmd}'", tag="CMD")
            if cmd in ["kill", "crash", "stop"]:
                self.log("EXECUTING REMOTE KILL: Terminating node & commanding disarm...", tag="ALERT")
                if self.mavlink.is_connected:
                    self.mavlink.command_emergency_land()
                fail_pkt = SwarmPacket(
                    msg_type=MessageType.ALERT_NODE_FAILURE,
                    sender_id=self.node_id,
                    payload={"failed_id": self.node_id, "waypoint_idx": self.current_wp_idx, "reason": "Operator Crash Injection", "timestamp": time.time()},
                    sequence_num=self.seq_num
                )
                self._publish_mesh("swarm/alerts", fail_pkt.serialize())
                threading.Thread(target=self.stop, daemon=True).start()
            elif cmd in ["land", "emergency"]:
                self.trigger_emergency_land_and_backup(reason="Remote Operator Command")
            elif cmd.startswith("takeoff"):
                parts = cmd.split()
                alt = float(parts[1]) if len(parts) > 1 and parts[1].replace('.', '', 1).isdigit() else self.takeoff_alt
                self.log(f"REMOTE TAKEOFF to {alt:.1f}m commanded...", tag="NAV")
                self.mavlink.command_arm_and_takeoff(target_alt_m=alt, force=self.force_arm)
                self.status = "FLYING"
            elif cmd == "arm":
                self.log("REMOTE ARM commanded...", tag="NAV")
                self.mavlink.set_mode("GUIDED")
                self.mavlink.arm(force=self.force_arm)
            elif cmd.startswith("rekey"):
                parts = cmd.split()
                lvl = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 768
                self.log(f"MANUAL REKEY to ML-KEM-{lvl} triggered...", tag="WARN")
                for p in ["drone_1", "drone_2", "drone_3", "backup_drone"]:
                    if p != self.node_id and not self.controller.is_isolated(p):
                        self.initiate_pqc_handshake(p, kyber_level=lvl)
            elif cmd.startswith("isolate"):
                parts = cmd.split()
                if len(parts) > 1:
                    target = parts[1]
                    self.quarantine_peer(target, reason="Operator Remote Isolation")
            elif cmd.startswith("unquarantine"):
                parts = cmd.split()
                if len(parts) > 1:
                    target = parts[1]
                    self.controller.unquarantine_peer(target)
                    self._subscribe_peer(target)
                    self.initiate_pqc_handshake(target, kyber_level=512)
            elif cmd in ["backup", "call backup"]:
                self.trigger_emergency_land_and_backup(reason="Manual Operator Call Backup")
            elif cmd == "status":
                snap = self.mavlink.get_telemetry_snapshot()
                self.log(f"STATUS SNAPSHOT: Role={self.role} | Status={self.status} | Battery={self.battery_voltage:.2f}V | Alt={self.alt}m | WP={self.current_wp_idx} | MAVLink={self.mavlink.is_connected}", tag="INFO")
        except Exception as e:
            self.log(f"Remote command parse error: {e}", tag="WARN")


# ─────────────────────────────────────────────────────────────
# CLI Runner
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Decentralized Autonomous UAV Swarm Node with PQC and AI IDS")
    parser.add_argument("--id", type=str, default="drone_1", help="UAV Node ID (e.g. drone_1, drone_2, backup_drone)")
    parser.add_argument("--role", type=str, default="primary", choices=["primary", "backup"], help="Swarm role (primary or backup)")
    parser.add_argument("--broker", type=str, default="127.0.0.1", help="Local MQTT broker IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=1883, help="MQTT broker port (default: 1883)")
    parser.add_argument("--peers", nargs="*", default=[], help="List of peer broker IPs (e.g. 100.125.195.19 192.168.1.10)")
    parser.add_argument("--freq", type=float, default=3.0, help="Telemetry frequency in Hz (default: 3.0)")
    parser.add_argument("--duration", type=float, default=300.0, help="Duration in seconds (default: 300.0)")
    parser.add_argument("--mavlink", type=str, default=None, help="Cube Orange MAVLink connection string (e.g. /dev/ttyACM0, /dev/ttyAMA0, COM3, udp:127.0.0.1:14550)")
    parser.add_argument("--mavlink-baud", type=int, default=57600, help="Cube Orange serial baud rate (default: 57600)")
    parser.add_argument("--battery", type=float, default=None, help="Battery voltage in Volts (e.g. 12.4, 11.2)")
    parser.add_argument("--health", type=float, default=0.98, help="Present health condition score [0.0 - 1.0]")
    parser.add_argument("--gps-strength", type=float, default=0.95, help="GPS link signal quality [0.0 - 1.0]")
    parser.add_argument("--gps-sats", type=int, default=14, help="Visible GPS satellite count")
    parser.add_argument("--gps-hdop", type=float, default=0.8, help="Horizontal Dilution of Precision (HDOP)")
    parser.add_argument("--force-arm", action="store_true", help="DANGEROUS: Bypass ArduPilot pre-arm checks (bench diagnosis only)")
    parser.add_argument("--radius", type=float, default=2.0, help="Waypoint acceptance radius in meters (default: 2.0)")
    parser.add_argument("--speed", type=float, default=3.0, help="Horizontal flight speed in m/s (default: 3.0)")
    parser.add_argument("--takeoff-alt", type=float, default=5.0, help="Autonomous takeoff altitude in meters (default: 5.0)")
    parser.add_argument("--no-auto-takeoff", action="store_true", help="Do not automatically arm and takeoff primary drone upon launch")
    args = parser.parse_args()

    node = DecentralizedSwarmNode(
        node_id=args.id,
        local_broker_host=args.broker,
        local_broker_port=args.port,
        peer_brokers=args.peers,
        role=args.role,
        frequency_hz=args.freq,
        mission_duration_sec=args.duration,
        mavlink_connection=args.mavlink,
        mavlink_baud=args.mavlink_baud,
        battery_voltage=args.battery,
        health_score=args.health,
        gps_strength=args.gps_strength,
        gps_sats=args.gps_sats,
        gps_hdop=args.gps_hdop,
        force_arm=args.force_arm,
        auto_takeoff=(not args.no_auto_takeoff),
        takeoff_alt=args.takeoff_alt,
        acceptance_radius_m=args.radius,
        speed_m_s=args.speed
    )

    def interactive_cli():
        print(f"[*] Commands available: [b] Emergency Land & Trigger Backup | [t] Takeoff | [status] Print Telemetry | [q] Quit\n")
        while node.running:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                cmd = line.strip().lower()
                if cmd in ("b", "backup", "land"):
                    node.trigger_emergency_land_and_backup(reason="Operator manual 'b' hotkey trigger")
                elif cmd in ("t", "takeoff"):
                    node.log(f"MANUAL TAKEOFF commanded to {node.takeoff_alt:.1f}m...", tag="NAV")
                    threading.Thread(target=node._primary_takeoff_worker, daemon=True).start()
                elif cmd == "status":
                    snap = node.mavlink.get_telemetry_snapshot()
                    node.log(f"STATUS SNAPSHOT: Node={node.node_id}, Status={node.status}, Lat={node.lat:.6f}, Lon={node.lon:.6f}, Alt={node.alt:.1f}m, Bat={node.battery_voltage:.2f}V, MAVLink_Connected={node.mavlink.is_connected}", tag="INFO")
                elif cmd in ("q", "quit", "exit"):
                    node.stop()
                    break
            except Exception:
                break

    try:
        node.start()
        cli_t = threading.Thread(target=interactive_cli, daemon=True)
        cli_t.start()
        print(f"\n[*] UAV Swarm Node '{args.id}' running. Press 'b' + Enter to Land & Trigger Backup, or Ctrl+C to terminate.\n")
        while node.running:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nTerminating node...")
    finally:
        node.stop()


if __name__ == "__main__":
    main()
