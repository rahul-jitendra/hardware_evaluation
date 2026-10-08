"""
spoof_attack.py — Rogue Peer Telemetry Spoofing & GPS Manipulation Attack
========================================================================
Simulates a compromised peer in the UAV swarm injecting erratic GPS coordinates,
excessive velocities (>55 m/s), and abnormal altitude shifts.
Demonstrates:
- Peer AI IDS detection via XGBoost + Isolation Forest + Conformal Prediction
- Trust decay (T_peer drops < 0.35)
- Security Ladder escalation to Kyber-1024
- Quarantine of the rogue peer and autonomous backup drone takeover!
"""

import sys
import os
import time
import json
import argparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import paho.mqtt.client as mqtt
from protocol import MessageType, SwarmPacket


def main():
    parser = argparse.ArgumentParser(description="Swarm GPS Spoofing Attack Simulator")
    parser.add_argument("--broker", type=str, default="127.0.0.1", help="Target MQTT broker IP")
    parser.add_argument("--port", type=int, default=1883, help="Target MQTT broker port")
    parser.add_argument("--attacker-id", type=str, default="drone_2", help="Compromised drone ID")
    parser.add_argument("--count", type=int, default=15, help="Number of spoofed packets to inject")
    args = parser.parse_args()

    try:
        from paho.mqtt.enums import CallbackAPIVersion
        client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id=f"attacker_{int(time.time())}")
    except Exception:
        client = mqtt.Client(client_id=f"attacker_{int(time.time())}")
    client.connect(args.broker, args.port, keepalive=60)
    client.loop_start()

    print("=" * 70)
    print(f"[*] LAUNCHING TELEMETRY SPOOFING ATTACK ON SWARM")
    print(f"[*] Target Broker : {args.broker}:{args.port}")
    print(f"[*] Attacker ID   : {args.attacker_id} (Impersonating / Compromised)")
    print(f"[*] Packets to Inject: {args.count}")
    print("=" * 70)

    seq = 999000
    base_lat = 16.792406
    base_lon = 80.819767

    for i in range(args.count):
        # Create an erratic coordinate jump (> 80 m/s velocity)
        jump_lat = base_lat + (i * 0.0080)
        jump_lon = base_lon + (i * 0.0075)

        spoofed_telem = {
            "drone_id": args.attacker_id,
            "lat": round(jump_lat, 6),
            "lon": round(jump_lon, 6),
            "alt": round(15.0 + (i * 8.0), 2),   # Abnormal vertical climb
            "voltage": 9.20,                     # Fake depleted battery
            "current": -0.01,
            "status": "FLYING",
            "seq": seq + i
        }

        # Inject as plain discovery / unencrypted payload to simulate compromised node
        packet = SwarmPacket(
            msg_type=MessageType.PQC_ENCRYPTED_TELEMETRY,
            sender_id=args.attacker_id,
            payload={"plain_discovery": spoofed_telem},
            sequence_num=seq + i
        )

        topic = f"swarm/pqc/{args.attacker_id}/telemetry"
        client.publish(topic, packet.serialize(), qos=1)
        print(f"[ATTACK -> INJECTED #{i+1}] Lat: {jump_lat:.6f}, Lon: {jump_lon:.6f}, Alt: {spoofed_telem['alt']}m")
        time.sleep(0.4)

    print("\n[*] Spoof injection complete. Observe swarm peers detecting intrusion and isolating rogue node.")
    time.sleep(2.0)
    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    main()
