"""
ai/trust_manager.py
====================
Feature 3 — Continuous UAV Trust Score
=======================================
Replaces binary intruder_flag with a continuous trust score T ∈ [0, 1]
updated as an Exponential Moving Average (EMA) of IDS P(intruder) scores.

Formula:
    T_new = (1 - decay) * T_old + decay * (1 - P_intruder)

  decay_attack  = 0.6  (trust drops fast on threat signal)
  decay_recover = 0.1  (trust recovers slowly after clean windows)

This asymmetry models real UAV behaviour:
  - A legitimate UAV that briefly looks suspicious recovers slowly
  - An intruder cannot quickly rebuild trust even if it goes quiet

Published metrics:
  - trust_score per snapshot window  → trust_trajectory.csv
  - trust_at_first_detection
  - trust_recovery_time_ms (time to recover from false alarm back above 0.7)
  - mean_trust_normal_uavs vs mean_trust_intruders  (key comparison table)
"""

import threading
import time
from datetime import datetime
from typing   import Optional


# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────

TRUST_INIT       = 1.0   # all new connections start at full trust
DECAY_ATTACK     = 0.6   # fast drop when P(intruder) is high
DECAY_RECOVER    = 0.1   # slow rise when P(intruder) is low
THREAT_THRESHOLD = 0.50  # P(intruder) above this = "attack signal"

# Trust thresholds that map to security level suggestions
TRUST_LEVELS = {
    "NORMAL":   0.75,   # T >= 0.75
    "ELEVATED": 0.50,   # 0.50 <= T < 0.75
    "HIGH":     0.25,   # 0.25 <= T < 0.50
    "CRITICAL": 0.00,   # T < 0.25
}

# Recovery threshold: T must rise back above this to count as "recovered"
RECOVERY_THRESHOLD = 0.70


# ─────────────────────────────────────────────────────────────
# Per-client trust state
# ─────────────────────────────────────────────────────────────

class ClientTrustState:
    def __init__(self, hostname: str, connect_time: datetime):
        self.hostname         = hostname
        self.connect_time     = connect_time

        self.trust            = TRUST_INIT
        self.history          = [TRUST_INIT]   # full trajectory list
        self.window_count     = 0

        # Detection tracking
        self.below_recovery   = False          # currently in "damaged" state
        self.damage_start_ms  = None           # when trust first dropped below RECOVERY_THRESHOLD
        self.recovery_times   = []             # list of recovery durations in ms

        # Aggregates
        self.min_trust        = TRUST_INIT
        self.max_trust        = TRUST_INIT
        self.sum_trust        = TRUST_INIT
        self.n_samples        = 1

    def update(self, intruder_prob: float) -> float:
        """
        Update trust score from one IDS snapshot.
        Returns the new trust score.
        """
        trust_signal = 1.0 - intruder_prob   # high prob → low trust signal

        if intruder_prob >= THREAT_THRESHOLD:
            decay = DECAY_ATTACK
        else:
            decay = DECAY_RECOVER

        self.trust = (1.0 - decay) * self.trust + decay * trust_signal
        self.trust = max(0.0, min(1.0, self.trust))

        self.window_count  += 1
        self.history.append(round(self.trust, 6))
        self.n_samples     += 1
        self.sum_trust     += self.trust
        self.min_trust      = min(self.min_trust, self.trust)
        self.max_trust      = max(self.max_trust, self.trust)

        # Track recovery
        now_ms = (datetime.now() - self.connect_time).total_seconds() * 1000
        if self.trust < RECOVERY_THRESHOLD and not self.below_recovery:
            self.below_recovery  = True
            self.damage_start_ms = now_ms
        elif self.trust >= RECOVERY_THRESHOLD and self.below_recovery:
            if self.damage_start_ms is not None:
                self.recovery_times.append(round(now_ms - self.damage_start_ms, 2))
            self.below_recovery  = False
            self.damage_start_ms = None

        return self.trust

    def trust_level_label(self) -> str:
        if self.trust >= TRUST_LEVELS["NORMAL"]:
            return "TRUSTED"
        elif self.trust >= TRUST_LEVELS["ELEVATED"]:
            return "UNCERTAIN"
        elif self.trust >= TRUST_LEVELS["HIGH"]:
            return "SUSPICIOUS"
        else:
            return "UNTRUSTED"

    def mean_trust(self) -> float:
        return round(self.sum_trust / self.n_samples, 6)

    def mean_recovery_ms(self) -> Optional[float]:
        if self.recovery_times:
            return round(sum(self.recovery_times) / len(self.recovery_times), 2)
        return None

    def summary(self) -> dict:
        return {
            "hostname":              self.hostname,
            "final_trust":           round(self.trust, 6),
            "min_trust":             round(self.min_trust, 6),
            "max_trust":             round(self.max_trust, 6),
            "mean_trust":            self.mean_trust(),
            "trust_level":           self.trust_level_label(),
            "total_windows":         self.window_count,
            "num_recovery_events":   len(self.recovery_times),
            "mean_recovery_ms":      self.mean_recovery_ms(),
            "trust_trajectory":      self.history,
        }


# ─────────────────────────────────────────────────────────────
# TrustManager  (server-level registry)
# ─────────────────────────────────────────────────────────────

class TrustManager:
    """
    Thread-safe registry of per-client trust states.
    Called by AdaptiveSecurityEngine after every IDS evaluation.
    """

    def __init__(self):
        self._states: dict = {}
        self._lock   = threading.Lock()

    def register(self, client_addr: tuple, hostname: str,
                 connect_time: datetime):
        with self._lock:
            if client_addr not in self._states:
                self._states[client_addr] = ClientTrustState(hostname, connect_time)

    def update(self, client_addr: tuple, intruder_prob: float) -> float:
        """Update trust and return new score. Returns 0.5 if client unknown."""
        with self._lock:
            state = self._states.get(client_addr)
        if state is None:
            return 0.5
        return state.update(intruder_prob)

    def get_trust(self, client_addr: tuple) -> float:
        with self._lock:
            state = self._states.get(client_addr)
        return state.trust if state else TRUST_INIT

    def get_alpha(self, client_addr: tuple) -> float:
        """Return Kyber weight alpha derived from trust (for Hybrid KEM)."""
        from key_encapsulation.hybrid_kem import trust_to_alpha
        return trust_to_alpha(self.get_trust(client_addr))

    def get_history(self, client_addr: tuple) -> list:
        with self._lock:
            state = self._states.get(client_addr)
        return state.history[:] if state else []

    def remove(self, client_addr: tuple) -> Optional[dict]:
        """Remove client and return final summary dict."""
        with self._lock:
            state = self._states.pop(client_addr, None)
        return state.summary() if state else None

    def all_summaries(self) -> list:
        with self._lock:
            return [s.summary() for s in self._states.values()]
