"""
swarm_adaptive_controller.py — Decentralized Security Controller & Rogue Isolation
===================================================================================
Manages:
1. Dynamic 3-Tier Security Escalation Ladder (Kyber-512 -> 768 -> 1024)
2. Dynamic trust-driven secret derivation weight: alpha = 1.0 - Trust
3. Peer quarantine / cryptographic rogue node isolation
4. Broadcast of Swarm Rogue Alerts & Backup Drone mission takeover triggers
"""

import time
from typing import Dict, Any, Tuple
from ai.peer_trust_manager import PeerTrustManager


class SwarmAdaptiveController:
    def __init__(self, trust_manager: PeerTrustManager):
        self.trust_mgr = trust_manager
        # Per-peer security level state (512, 768, 1024)
        self.peer_kyber_levels: Dict[str, int] = {}
        self.peer_isolated: Dict[str, bool] = {}
        self.rekey_counts: Dict[str, int] = {}
        self.last_rekey_times: Dict[str, float] = {}

    def get_kyber_level(self, peer_id: str) -> int:
        return self.peer_kyber_levels.get(peer_id, 512)

    def is_isolated(self, peer_id: str) -> bool:
        return self.peer_isolated.get(peer_id, False)

    def unquarantine_peer(self, peer_id: str):
        """Un-quarantines a peer (e.g. upon operator restore / node reboot)."""
        self.peer_isolated[peer_id] = False
        self.peer_kyber_levels[peer_id] = 512
        self.trust_mgr.reset_peer(peer_id)

    def evaluate_peer(self, peer_id: str, ids_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates IDS evaluation metrics against peer trust and security ladder.
        Returns:
          new_kyber_level, rekey_needed, isolate_peer, reason, alpha
        """
        threat_prob = ids_result["threat_prob"]
        is_anomaly = ids_result["is_anomaly"]
        conformal_set = ids_result.get("conformal_set", "{Normal}")

        # Update peer trust
        trust = self.trust_mgr.update_trust(peer_id, threat_prob, is_anomaly)
        alpha = round(max(0.0, min(1.0, 1.0 - trust)), 4)

        prev_level = self.get_kyber_level(peer_id)
        new_level = prev_level
        rekey_needed = False
        isolate_peer = False
        reason = "Nominal swarm operation"

        # Sequential Adaptive Security Ladder (512 -> 768 -> 1024 -> Isolation)
        if prev_level == 512:
            if threat_prob >= 0.65 or trust < 0.70 or conformal_set != "{Normal}":
                new_level = 768
                reason = f"Elevated anomaly detected ({conformal_set}, Threat={threat_prob:.2f}, Trust={trust:.2f}). Escalating to ML-KEM-768."
        elif prev_level == 768:
            if threat_prob >= 0.75 or trust < 0.50 or conformal_set == "{Intruder}":
                new_level = 1024
                reason = f"Persistent / High threat ({conformal_set}, Threat={threat_prob:.2f}, Trust={trust:.2f}). Escalating to ML-KEM-1024."
            elif threat_prob < 0.15 and trust > 0.75 and conformal_set == "{Normal}":
                new_level = 512
                reason = f"Swarm trust restored ({conformal_set}, Trust={trust:.2f}). De-escalating to ML-KEM-512."
        elif prev_level == 1024:
            if trust < 0.30:
                isolate_peer = True
                reason = f"CRITICAL THREAT: Rogue peer trust collapse ({conformal_set}, Trust={trust:.2f}). Isolating peer!"
                self.peer_isolated[peer_id] = True
            elif threat_prob < 0.20 and trust > 0.60 and conformal_set == "{Normal}":
                new_level = 768
                reason = f"Threat subsiding ({conformal_set}, Trust={trust:.2f}). De-escalating to ML-KEM-768."

        if new_level != prev_level:
            rekey_needed = True
            self.peer_kyber_levels[peer_id] = new_level
            self.rekey_counts[peer_id] = self.rekey_counts.get(peer_id, 0) + 1
            self.last_rekey_times[peer_id] = time.time()

        return {
            "peer_id": peer_id,
            "trust": trust,
            "alpha": alpha,
            "kyber_level": new_level,
            "previous_level": prev_level,
            "rekey_needed": rekey_needed,
            "isolate_peer": isolate_peer,
            "reason": reason
        }
