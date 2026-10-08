"""
optimal_backup_selector.py — Multi-Criteria Optimal Backup UAV Selection Engine
==============================================================================
Implements Algorithm 1 (Enhanced): Multi-Criteria Optimal Backup UAV Selection & Mission Continuity.

When an active primary drone encounters a critical fault (sudden crash, silent heartbeat loss,
emergency landing breach, or rogue node quarantine), this module evaluates all idle/standby
backup drones in the swarm pool and selects the mathematically optimal replacement.

Optimization Criteria:
  1. Battery Voltage / State of Charge (E_hat): Preserves flight endurance for mission completion.
  2. Present Health Condition (H_hat): Hardware, motor integrity, IMU vibration, and CPU thermals.
  3. GPS Link Strength & Constellation Geometry (G_hat): Satellite count and HDOP navigation precision.
  4. Spatial Proximity / Distance to Target Waypoint (D_hat): Minimizes transit time and recovery delay.
  5. Decentralized Peer Trust Score (T_hat): AI IDS continuous trust score, enforcing zero-trust exclusion
     of compromised, anomalous, or quarantined candidate drones.
"""

import math
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field


def haversine_distance_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculates great-circle distance between two GPS coordinates in meters."""
    R = 6371000.0  # Earth radius in meters
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2.0)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0)**2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return R * c


@dataclass
class BackupCandidateState:
    node_id: str
    lat: float
    lon: float
    alt: float
    voltage: float
    health_score: float = 1.0       # [0.0 - 1.0] (1.0 = pristine motor/IMU health)
    gps_strength: float = 0.95      # [0.0 - 1.0] (Composite GPS signal quality)
    gps_sats: int = 12              # Visible satellite count
    gps_hdop: float = 0.8           # Horizontal Dilution of Precision
    trust_score: float = 1.0        # AI IDS Peer Trust Score [0.0 - 1.0]
    status: str = "STANDBY"         # Must be "STANDBY" or "IDLE"
    is_isolated: bool = False       # True if quarantined by security controller
    last_seen: float = field(default_factory=time.time)


class OptimalBackupSelector:
    def __init__(self,
                 w_battery: float = 0.25,
                 w_health: float = 0.15,
                 w_gps: float = 0.15,
                 w_distance: float = 0.25,
                 w_trust: float = 0.20,
                 v_cutoff: float = 10.20,
                 v_nominal: float = 12.60,
                 min_health_threshold: float = 0.60,
                 min_gps_threshold: float = 0.40,
                 min_trust_threshold: float = 0.50,
                 d_reference_m: float = 300.0):
        """
        Initializes the Multi-Criteria Optimal Backup Selector.
        Weights default to Pareto-optimal balanced distribution (sum = 1.0).
        """
        total_w = w_battery + w_health + w_gps + w_distance + w_trust
        self.w_battery = w_battery / total_w
        self.w_health = w_health / total_w
        self.w_gps = w_gps / total_w
        self.w_distance = w_distance / total_w
        self.w_trust = w_trust / total_w

        self.v_cutoff = v_cutoff
        self.v_nominal = v_nominal
        self.min_health = min_health_threshold
        self.min_gps = min_gps_threshold
        self.min_trust = min_trust_threshold
        self.d_ref_m = d_reference_m

    def normalize_battery(self, voltage: float) -> float:
        """Normalizes voltage against usable operational range [V_cutoff, V_nominal]."""
        if voltage <= self.v_cutoff:
            return 0.0
        norm = (voltage - self.v_cutoff) / (self.v_nominal - self.v_cutoff)
        return max(0.0, min(1.0, norm))

    def normalize_gps(self, strength: float, sats: int, hdop: float) -> float:
        """Calculates normalized GPS quality combining signal strength and satellite geometry."""
        # Baseline from direct strength or satellite geometry
        geom_factor = min(1.0, (sats / 14.0) * (1.0 / max(0.6, hdop)))
        combined = 0.6 * strength + 0.4 * geom_factor
        return max(0.0, min(1.0, combined))

    def normalize_distance(self, dist_m: float) -> float:
        """Decaying exponential proximity metric (closer distance yields higher utility)."""
        # Distance utility: 1.0 at 0m, ~0.37 at d_ref, ~0.05 at 3*d_ref
        return math.exp(-dist_m / self.d_ref_m)

    def evaluate_candidate(self,
                           candidate: BackupCandidateState,
                           target_lat: float,
                           target_lon: float) -> Dict[str, Any]:
        """
        Evaluates a single candidate backup drone against all 5 criteria.
        Returns utility score breakdown and eligibility status.
        """
        # 1. Eligibility Hard Constraints
        reasons_ineligible = []
        if candidate.is_isolated:
            reasons_ineligible.append("Quarantined by AI IDS security controller")
        if candidate.status not in ("STANDBY", "IDLE"):
            reasons_ineligible.append(f"Drone is currently busy (Status: {candidate.status})")
        if candidate.voltage < self.v_cutoff + 0.30:  # Minimum 10.50V required for flight
            reasons_ineligible.append(f"Depleted battery ({candidate.voltage:.2f}V < {self.v_cutoff + 0.30:.2f}V)")
        if candidate.health_score < self.min_health:
            reasons_ineligible.append(f"Degraded hardware health ({candidate.health_score:.2f} < {self.min_health})")
        if candidate.trust_score < self.min_trust:
            reasons_ineligible.append(f"Low peer trust ({candidate.trust_score:.2f} < {self.min_trust})")

        is_eligible = len(reasons_ineligible) == 0

        # 2. Individual Sub-Criteria Normalization
        dist_m = haversine_distance_m(candidate.lat, candidate.lon, target_lat, target_lon)
        e_hat = self.normalize_battery(candidate.voltage)
        h_hat = max(0.0, min(1.0, candidate.health_score))
        g_hat = self.normalize_gps(candidate.gps_strength, candidate.gps_sats, candidate.gps_hdop)
        d_hat = self.normalize_distance(dist_m)
        t_hat = max(0.0, min(1.0, candidate.trust_score))

        # 3. Multi-Attribute Composite Utility Score
        if is_eligible:
            score = (self.w_battery * e_hat +
                     self.w_health * h_hat +
                     self.w_gps * g_hat +
                     self.w_distance * d_hat +
                     self.w_trust * t_hat)
        else:
            score = 0.0

        return {
            "node_id": candidate.node_id,
            "is_eligible": is_eligible,
            "disqualification_reasons": reasons_ineligible,
            "distance_m": round(dist_m, 2),
            "e_battery_norm": round(e_hat, 4),
            "h_health_norm": round(h_hat, 4),
            "g_gps_norm": round(g_hat, 4),
            "d_dist_norm": round(d_hat, 4),
            "t_trust_norm": round(t_hat, 4),
            "composite_score": round(score, 4),
            "raw_voltage": candidate.voltage,
            "raw_health": candidate.health_score,
            "raw_gps_sats": candidate.gps_sats,
            "raw_gps_hdop": candidate.gps_hdop,
            "raw_trust": candidate.trust_score
        }

    def select_optimal_backup(self,
                              candidates: List[BackupCandidateState],
                              target_lat: float,
                              target_lon: float) -> Tuple[Optional[BackupCandidateState], Dict[str, Any]]:
        """
        Evaluates the entire pool of candidate backup drones and selects the optimal UAV (B*).
        Returns:
          (selected_candidate, audit_report)
        """
        if not candidates:
            return None, {"error": "No backup candidate drones available in pool", "rankings": []}

        evaluations = []
        eligible_candidates = []

        for cand in candidates:
            ev = self.evaluate_candidate(cand, target_lat, target_lon)
            evaluations.append(ev)
            if ev["is_eligible"]:
                eligible_candidates.append((cand, ev["composite_score"]))

        # Sort all evaluations by score descending
        evaluations.sort(key=lambda x: x["composite_score"], reverse=True)

        if not eligible_candidates:
            return None, {
                "winner": None,
                "winner_score": 0.0,
                "eligible_count": 0,
                "total_candidates": len(candidates),
                "rankings": evaluations,
                "note": "All candidate drones disqualified based on safety/health/trust constraints"
            }

        # Select candidate with maximum utility score
        eligible_candidates.sort(key=lambda item: item[1], reverse=True)
        winner_candidate, best_score = eligible_candidates[0]

        report = {
            "winner": winner_candidate.node_id,
            "winner_score": best_score,
            "eligible_count": len(eligible_candidates),
            "total_candidates": len(candidates),
            "rankings": evaluations,
            "criteria_weights": {
                "w_battery": self.w_battery,
                "w_health": self.w_health,
                "w_gps": self.w_gps,
                "w_distance": self.w_distance,
                "w_trust": self.w_trust
            }
        }

        return winner_candidate, report
