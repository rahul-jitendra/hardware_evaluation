"""
peer_trust_manager.py — Decentralized Peer Trust Score Manager
===============================================================
Maintains continuous trust scores T_j in [0.0, 1.0] for every peer UAV in the swarm.
Uses asymmetric exponential moving average (EMA):
  - Fast decay when threat/anomaly is detected
  - Slow, gradual recovery under nominal conditions
"""

import time
from typing import Dict, Any, Tuple


class PeerTrustManager:
    def __init__(self,
                 decay_attack: float = 0.32,
                 decay_recover: float = 0.010,
                 initial_trust: float = 1.0):
        self.decay_attack = decay_attack
        self.decay_recover = decay_recover
        self.initial_trust = initial_trust
        self.peer_trust: Dict[str, float] = {}
        self.last_update: Dict[str, float] = {}
        self.history: Dict[str, list] = {}

    def register_peer(self, peer_id: str):
        if peer_id not in self.peer_trust:
            self.peer_trust[peer_id] = self.initial_trust
            self.last_update[peer_id] = time.time()
            self.history[peer_id] = [(time.time(), self.initial_trust)]

    def reset_peer(self, peer_id: str):
        """Resets peer trust score to nominal 1.0."""
        self.peer_trust[peer_id] = self.initial_trust
        self.last_update[peer_id] = time.time()
        if peer_id in self.history:
            self.history[peer_id].append((time.time(), self.initial_trust))

    def update_trust(self, peer_id: str, threat_prob: float, is_anomaly: bool) -> float:
        """
        Updates peer trust score:
        threat_prob: combined threat score in [0.0, 1.0]
        """
        if peer_id not in self.peer_trust:
            self.register_peer(peer_id)

        current_trust = self.peer_trust[peer_id]

        if is_anomaly or threat_prob >= 0.70:
            # Threat detected: fast exponential decay
            decay = self.decay_attack
            new_trust = max(0.0, (1.0 - decay) * current_trust + decay * (1.0 - threat_prob))
        else:
            # Nominal behavior: gradual trust recovery
            decay = self.decay_recover
            new_trust = min(1.0, (1.0 - decay) * current_trust + decay * 1.0)

        self.peer_trust[peer_id] = round(new_trust, 4)
        self.last_update[peer_id] = time.time()
        self.history[peer_id].append((time.time(), self.peer_trust[peer_id]))
        if len(self.history[peer_id]) > 500:
            self.history[peer_id].pop(0)

        return self.peer_trust[peer_id]

    def get_trust(self, peer_id: str) -> float:
        return self.peer_trust.get(peer_id, self.initial_trust)

    def is_peer_untrusted(self, peer_id: str, cutoff: float = 0.35) -> bool:
        """Returns True if peer trust has fallen below the quarantine threshold."""
        return self.get_trust(peer_id) < cutoff
