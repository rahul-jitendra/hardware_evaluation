"""
run_full_swarm_test.py — 4-UAV Decentralized PQC Swarm Orchestrator
====================================================================
Spawns 4 autonomous UAV nodes in a single execution environment:
- Drone 1 (Primary)
- Drone 2 (Primary)
- Drone 3 (Primary)
- Backup Drone (Autonomous Standby)

Provides an interactive CLI:
- Press 's' + Enter : Trigger GPS Spoofing Attack on Drone 2
- Press 'k' + Enter : Simulate Silent Failure / Crash of Drone 1 (10s timeout test)
- Press 'q' + Enter : Graceful Swarm Shutdown
"""

import sys
import os
import time
import subprocess
import threading

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from swarm_node import DecentralizedSwarmNode


def main():
    print("=" * 80)
    print("   DECENTRALIZED POST-QUANTUM ADAPTIVE UAV SWARM FRAMEWORK (4 NODES)")
    print("   - Mutual Hybrid PQC (ECC-P256 + CRYSTALS-Kyber KEM 512/768/1024)")
    print("   - Inductive Mondrian Conformal Prediction AI IDS (alpha=0.05)")
    print("   - Dynamic Trust Weighting (alpha = 1 - Trust)")
    print("   - Autonomous Backup Drone Mission Handover (Sajid et al. Eq. 4)")
    print("=" * 80)

    # 1. Initialize 4 Nodes
    d1 = DecentralizedSwarmNode(node_id="drone_1", role="primary", frequency_hz=2.0)
    d2 = DecentralizedSwarmNode(node_id="drone_2", role="primary", frequency_hz=2.0)
    d3 = DecentralizedSwarmNode(node_id="drone_3", role="primary", frequency_hz=2.0)
    backup = DecentralizedSwarmNode(node_id="backup_drone", role="backup", frequency_hz=2.0)

    nodes = [d1, d2, d3, backup]

    print("\n[*] Starting all 4 autonomous swarm nodes...")
    for n in nodes:
        n.start()
        time.sleep(0.5)

    print("\n" + "=" * 80)
    print("   SWARM ACTIVE! INTERACTIVE TEST CONTROLS:")
    print("   [b] + Enter : Trigger On-Site Emergency Landing on Drone 2 & Activate Backup Drone")
    print("   [s] + Enter : Launch GPS Spoofing Attack on Drone 2 (Tests AI IDS & Rogue Isolation)")
    print("   [k] + Enter : Kill / Crash Drone 1 (Tests 10s Silent Timeout Failover)")
    print("   [q] + Enter : Terminate All Swarm Nodes")
    print("=" * 80 + "\n")

    try:
        while True:
            cmd = input().strip().lower()
            if cmd == 'q':
                break
            elif cmd == 'b':
                print("\n[!] OPERATOR 'b' PRESSED: Drone 2 initiating on-site landing & activating Backup Drone...")
                d2.trigger_emergency_land_and_backup(reason="CLI 'b' key operator landing")
            elif cmd == 's':
                print("\n[!] INJECTING GPS SPOOFING ATTACK ON DRONE 2...")
                subprocess.Popen([
                    sys.executable,
                    os.path.join(os.path.dirname(__file__), "attacks", "spoof_attack.py"),
                    "--attacker-id", "drone_2",
                    "--count", "10"
                ])
            elif cmd == 'k':
                print("\n[!] SIMULATING COMPLETE SILENT CRASH OF DRONE 1...")
                d1.stop()
                print("[*] Drone 1 stopped. Watch Backup Drone countdown 10 seconds and take over!")
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[*] Shutting down swarm...")
        for n in nodes:
            n.stop()
        print("[*] Swarm terminated cleanly.")


if __name__ == "__main__":
    main()
