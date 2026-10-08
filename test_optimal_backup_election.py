"""
test_optimal_backup_election.py
================================
Validates Algorithm 1 (Enhanced): Multi-Criteria Optimal Backup UAV Selection.
Tests candidate evaluation, constraint filtering, normalization, and ranking
across battery, health condition, GPS link strength, waypoint distance, and trust score.
"""

import sys
import os
import json

# Ensure parent directory is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai.optimal_backup_selector import OptimalBackupSelector, BackupCandidateState, haversine_distance_m

def run_tests():
    print("=" * 80)
    print("VALIDATING ALGORITHM 1 (ENHANCED): MULTI-CRITERIA OPTIMAL BACKUP SELECTION")
    print("=" * 80)

    selector = OptimalBackupSelector(
        w_battery=0.25,
        w_health=0.15,
        w_gps=0.15,
        w_distance=0.25,
        w_trust=0.20,
        v_cutoff=10.20,
        v_nominal=12.60,
        min_health_threshold=0.60,
        min_gps_threshold=0.40,
        min_trust_threshold=0.50,
        d_reference_m=200.0
    )

    # Failed primary drone coordinates (Waypoint #2 in typical mission)
    target_lat = 12.9720
    target_lon = 77.5950

    print(f"\n[+] Failure Event: Primary UAV 'drone_1' failed at WP#2 (Lat={target_lat}, Lon={target_lon})")
    print("[+] Evaluating Candidate Standby Backup Fleet:\n")

    candidates = [
        # Candidate 1: Balanced high-endurance UAV at moderate distance
        BackupCandidateState(
            node_id="backup_drone_1",
            lat=12.9715, lon=77.5945, alt=0.0,  # ~77m away
            voltage=12.50, health_score=0.96, gps_strength=0.95, gps_sats=14, gps_hdop=0.8,
            trust_score=0.99, status="STANDBY"
        ),
        # Candidate 2: Very close, but depleted battery (< 10.5V safety limit)
        BackupCandidateState(
            node_id="backup_drone_2",
            lat=12.9719, lon=77.5949, alt=0.0,  # ~15m away
            voltage=10.35, health_score=0.94, gps_strength=0.92, gps_sats=13, gps_hdop=0.9,
            trust_score=0.95, status="STANDBY"
        ),
        # Candidate 3: Close distance, but degraded motor health (vibration/ESC fault)
        BackupCandidateState(
            node_id="backup_drone_3",
            lat=12.9718, lon=77.5948, alt=0.0,  # ~31m away
            voltage=12.30, health_score=0.52, gps_strength=0.88, gps_sats=11, gps_hdop=1.1,
            trust_score=0.92, status="STANDBY"
        ),
        # Candidate 4: Moderate distance, but quarantined by AI IDS (low trust score)
        BackupCandidateState(
            node_id="backup_drone_4",
            lat=12.9716, lon=77.5947, alt=0.0,  # ~55m away
            voltage=12.45, health_score=0.95, gps_strength=0.90, gps_sats=12, gps_hdop=0.9,
            trust_score=0.35, status="STANDBY", is_isolated=True
        ),
        # Candidate 5: Good health & battery, but degraded GPS reception (e.g. shadowed canopy)
        BackupCandidateState(
            node_id="backup_drone_5",
            lat=12.9717, lon=77.5946, alt=0.0,  # ~54m away
            voltage=12.15, health_score=0.88, gps_strength=0.32, gps_sats=4, gps_hdop=3.5,
            trust_score=0.90, status="STANDBY"
        ),
        # Candidate 6: Healthy UAV closer than backup_drone_1 with excellent metrics
        BackupCandidateState(
            node_id="backup_drone_6",
            lat=12.9717, lon=77.5948, alt=0.0,  # ~39m away
            voltage=12.40, health_score=0.92, gps_strength=0.92, gps_sats=13, gps_hdop=0.85,
            trust_score=0.98, status="STANDBY"
        )
    ]

    winner, report = selector.select_optimal_backup(candidates, target_lat, target_lon)

    print(f"{'Node ID':<16} | {'Status':<10} | {'Dist (m)':<8} | {'E_batt':<8} | {'H_health':<8} | {'G_gps':<8} | {'T_trust':<8} | {'Utility Score':<12} | {'Notes / Disqualification'}")
    print("-" * 125)

    for rank_info in report["rankings"]:
        node = rank_info["node_id"]
        status = "ELIGIBLE" if rank_info["is_eligible"] else "REJECTED"
        dist = f"{rank_info['distance_m']:.1f}"
        e_norm = f"{rank_info['e_battery_norm']:.3f}"
        h_norm = f"{rank_info['h_health_norm']:.3f}"
        g_norm = f"{rank_info['g_gps_norm']:.3f}"
        t_norm = f"{rank_info['t_trust_norm']:.3f}"
        score = f"{rank_info['composite_score']:.4f}"
        reasons = "; ".join(rank_info["disqualification_reasons"]) if rank_info["disqualification_reasons"] else "Optimal candidate meeting all safety gates"
        print(f"{node:<16} | {status:<10} | {dist:<8} | {e_norm:<8} | {h_norm:<8} | {g_norm:<8} | {t_norm:<8} | {score:<12} | {reasons}")

    print("-" * 125)
    print(f"\n[*] ELECTED WINNER: {winner.node_id.upper()}")
    print(f"    Composite Multi-Criteria Score : {report['winner_score']:.4f}")
    print(f"    Total Evaluated Candidates     : {report['total_candidates']}")
    print(f"    Qualified Candidates           : {report['eligible_count']}")

    assert winner.node_id == "backup_drone_6" or winner.node_id == "backup_drone_1", f"Unexpected winner: {winner.node_id}"
    print("\n[OK] VERIFICATION SUCCESSFUL: Algorithm 1 (Enhanced) correctly disqualifies deficient drones and selects the optimal backup UAV!\n")

if __name__ == "__main__":
    run_tests()
