"""
ai/anomaly_velocity.py
========================
Feature B — Anomaly Velocity Tracking
=======================================
Tracks the RATE OF CHANGE of ensemble IDS score per client.
A rapidly rising score triggers early warning even before the
absolute score crosses an escalation threshold.

Why this matters for UAV security:
  - Stealth intruders ramp up their score slowly to avoid threshold triggers.
    The standard threshold-based system misses them.
  - Velocity detection catches them at the first sign of acceleration.

Mechanism:
  velocity = ensemble_score[t] - ensemble_score[t-1]   (per snapshot)
  acceleration = velocity[t] - velocity[t-1]            (second derivative)

Early Warning triggers when:
  velocity > VELOCITY_THRESHOLD   (0.15 default)
  OR acceleration > ACCEL_THRESHOLD  (0.10 default)

The early warning does NOT change the security level — it only:
  1. Logs to anomaly_velocity.csv
  2. Sets early_warning flag in SecurityDecision
  3. Reduces de-escalation grace windows from 3 to 1

This means: if a stealth intruder is detected via velocity,
the system becomes harder to de-escalate even if the absolute
score drops (the intruder can't quickly hide).

Publishable metrics:
  - TTD comparison: velocity vs threshold-only detection
  - Stealth intruder detection rate with/without velocity
  - False alarm rate: does velocity cause more false positives?
  - Mean velocity for normal UAVs vs intruders (key comparison table)
"""

import threading
from collections import deque
from datetime    import datetime
from typing      import Optional


VELOCITY_THRESHOLD  = 0.15   # score jump per window that triggers warning
ACCEL_THRESHOLD     = 0.10   # acceleration (2nd derivative) threshold
HISTORY_WINDOW      = 5      # number of recent scores to keep per client


class VelocityState:
    """Per-client velocity tracking state."""

    def __init__(self, hostname: str):
        self.hostname    = hostname
        self.history     = deque(maxlen=HISTORY_WINDOW)  # recent ensemble scores
        self.velocities  = deque(maxlen=HISTORY_WINDOW)  # recent velocities
        self.early_warning_count = 0
        self.max_velocity        = 0.0
        self.max_acceleration    = 0.0
        self.first_velocity_warning_ms: Optional[float] = None  # TTD via velocity
        self.connect_time        = datetime.now()

    def update(self, score: float, connect_time: datetime) -> dict:
        """
        Add new score, compute velocity and acceleration.
        Returns dict with velocity metrics and early_warning flag.
        """
        velocity     = 0.0
        acceleration = 0.0
        early_warning= False
        warning_type = "none"

        if len(self.history) >= 1:
            velocity = score - self.history[-1]

        if len(self.velocities) >= 1:
            acceleration = velocity - self.velocities[-1]

        self.history.append(score)
        self.velocities.append(velocity)

        # Update max
        self.max_velocity     = max(self.max_velocity,     abs(velocity))
        self.max_acceleration = max(self.max_acceleration, abs(acceleration))

        # Check early warning conditions
        if velocity > VELOCITY_THRESHOLD:
            early_warning = True
            warning_type  = "velocity"
        elif acceleration > ACCEL_THRESHOLD:
            early_warning = True
            warning_type  = "acceleration"

        if early_warning:
            self.early_warning_count += 1
            if self.first_velocity_warning_ms is None:
                self.first_velocity_warning_ms = (
                    datetime.now() - connect_time).total_seconds() * 1000

        # Trend: last 3 scores all rising?
        trend_rising = (len(self.history) >= 3 and
                        self.history[-1] > self.history[-2] > self.history[-3])

        return {
            "velocity":         round(velocity, 6),
            "acceleration":     round(acceleration, 6),
            "early_warning":    early_warning,
            "warning_type":     warning_type,
            "trend_rising":     trend_rising,
            "window_count":     len(self.history),
            "velocity_ttd_ms":  self.first_velocity_warning_ms,
        }

    def mean_velocity(self) -> float:
        v = list(self.velocities)
        return round(sum(v) / len(v), 6) if v else 0.0

    def summary(self) -> dict:
        return {
            "hostname":                  self.hostname,
            "early_warning_count":       self.early_warning_count,
            "max_velocity":              round(self.max_velocity, 6),
            "max_acceleration":          round(self.max_acceleration, 6),
            "mean_velocity":             self.mean_velocity(),
            "velocity_ttd_ms":           self.first_velocity_warning_ms,
            "score_history":             list(self.history),
        }


class AnomalyVelocityTracker:
    """
    Thread-safe registry of per-client velocity states.
    Called by AdaptiveSecurityEngine after every IDS evaluation.
    """

    def __init__(self):
        self._states: dict = {}
        self._lock   = threading.Lock()

    def register(self, client_addr: tuple, hostname: str, connect_time: datetime):
        with self._lock:
            state = VelocityState(hostname)
            state.connect_time = connect_time
            self._states[client_addr] = state

    def update(self, client_addr: tuple, score: float,
               connect_time: datetime) -> dict:
        """Returns velocity metrics. Empty dict if client not registered."""
        with self._lock:
            state = self._states.get(client_addr)
        if state is None:
            return {"velocity": 0.0, "acceleration": 0.0,
                    "early_warning": False, "warning_type": "none",
                    "trend_rising": False, "window_count": 0,
                    "velocity_ttd_ms": None}
        return state.update(score, connect_time)

    def get_summary(self, client_addr: tuple) -> Optional[dict]:
        with self._lock:
            state = self._states.get(client_addr)
        return state.summary() if state else None

    def remove(self, client_addr: tuple) -> Optional[dict]:
        with self._lock:
            state = self._states.pop(client_addr, None)
        return state.summary() if state else None
