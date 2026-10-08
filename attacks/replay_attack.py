"""
replay_attack.py — Cryptographic Packet Replay Attack Simulator
================================================================
Captures legitimate swarm telemetry packets and replays them back into
the network to test whether the DecentralizedProtocolEngine correctly
detects non-monotonic sequence numbers and stale timestamps.
"""

import sys
import os
import time
import argparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import paho.mqtt.client as mqtt
from protocol import SwarmPacket


def main():
    parser = argparse.ArgumentParser(description="Swarm Replay Attack Simulator")
    parser.add_argument("--broker", type=str, default="127.0.0.1", help="Target MQTT broker IP")
    parser.add_argument("--port", type=int, default=1883, help="Target MQTT broker port")
    parser.add_argument("--target-drone", type=str, default="drone_1", help="Drone to intercept and replay")
    args = parser.parse_args()

    captured_packets = []

    try:
        from paho.mqtt.enums import CallbackAPIVersion
        client = mqtt.Client(CallbackAPIVersion.VERSION2, client_id=f"replay_sniffer_{int(time.time())}")
    except Exception:
        client = mqtt.Client(client_id=f"replay_sniffer_{int(time.time())}")

    def on_connect(c, userdata, flags, rc, properties=None):
        c.subscribe(f"swarm/pqc/{args.target_drone}/telemetry", qos=1)
        print(f"[*] Sniffing packets from 'swarm/pqc/{args.target_drone}/telemetry'...")

    def on_message(c, userdata, msg):
        try:
            pkt = SwarmPacket.deserialize(msg.payload.decode('utf-8'))
            if pkt and len(captured_packets) < 5:
                captured_packets.append((msg.topic, msg.payload))
                print(f"[SNIFFED] Captured packet seq={pkt.sequence_num} from {pkt.sender_id}")
        except Exception:
            pass

    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(args.broker, args.port, keepalive=60)
    client.loop_start()

    print("[*] Waiting for 3 seconds to intercept live swarm packets...")
    time.sleep(3.0)

    if not captured_packets:
        print("[!] No packets intercepted. Ensure a swarm node is broadcasting.")
        client.loop_stop()
        return

    print(f"\n[*] INTERCEPTED {len(captured_packets)} PACKETS. EXECUTING REPLAY ATTACK...")
    for idx, (topic, raw_payload) in enumerate(captured_packets):
        time.sleep(0.5)
        client.publish(topic, raw_payload, qos=1)
        print(f"[REPLAY INJECT #{idx+1}] Re-published stale packet to {topic}")

    print("\n[*] Replay injection finished. Check receiving node logs to verify REPLAY DETECTED drops.")
    time.sleep(2.0)
    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    main()
