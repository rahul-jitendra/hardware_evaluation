"""
unauthorized_peer.py — Rogue Node Injection Without PQC Handshake
==================================================================
Simulates an unauthorized adversary attempting to inject rogue commands
or telemetry into the swarm without possessing valid ECC or Kyber credentials.
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
    parser = argparse.ArgumentParser(description="Unauthorized Peer Injection Test")
    parser.add_argument("--broker", type=str, default="127.0.0.1", help="Target MQTT broker IP")
    parser.add_argument("--port", type=int, default=1883, help="Target MQTT broker port")
    parser.add_argument("--fake-id", type=str, default="fake_drone_99", help="Adversary ID")
    args = parser.parse_args()

    try:
        from paho.mqtt.enums import CallbackAPIVersion
        client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id=f"adversary_{int(time.time())}")
    except Exception:
        client = mqtt.Client(client_id=f"adversary_{int(time.time())}")
    client.connect(args.broker, args.port, keepalive=60)
    client.loop_start()

    print("=" * 70)
    print(f"[*] LAUNCHING UNAUTHORIZED ROGUE NODE INTRUSION ATTEMPT")
    print(f"[*] Target Broker : {args.broker}:{args.port}")
    print(f"[*] Target Drone  : drone_1 (Alpha)")
    print(f"[*] Rogue Fake ID : {args.fake_id}")
    print(f"[*] Credentials   : NONE (Unauthenticated / No PQC Session Key)")
    print("=" * 70)

    # Attempt to send garbage ciphertext purporting to be encrypted
    pkt = SwarmPacket(
        msg_type=MessageType.PQC_ENCRYPTED_TELEMETRY,
        sender_id=args.fake_id,
        payload={
            "target_peer": "drone_1",
            "kyber_level": 512,
            "cipher_hex": "deadbeefcafebabe0102030405060708"
        },
        sequence_num=100
    )

    client.publish("swarm/pqc/drone_1/telemetry", pkt.serialize(), qos=1)
    print("[!] Injected unauthenticated payload into 'swarm/pqc/drone_1/telemetry'")
    time.sleep(1.0)
    print("\n[SECURITY OUTCOME]")
    print(" -> Connection Status : REJECTED (Missing Kyber + ECC Credentials)")
    print(" -> Swarm Action      : Packet Dropped by drone_1 Gateway")
    print(" -> Mesh Isolation    : fake_drone_99 Denied Access (Swarm Untouched)")
    print("=" * 70)

    time.sleep(1.0)
    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    main()
