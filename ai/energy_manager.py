"""
ai/energy_manager.py
=====================
Feature 5 — Energy-Aware Security Gating
==========================================
Monitors server CPU% in real time and adjusts the maximum
permitted Kyber parameter set based on available compute budget.

Rules:
  CPU < CPU_LOW   (30%):  server has headroom → allow proactive upgrade
                          to Kyber-1024 if threat is HIGH/CRITICAL
  CPU_LOW ≤ CPU < CPU_MID (30–60%): normal operation, no interference
  CPU_MID ≤ CPU < CPU_HIGH (60–80%): cap at Kyber-768 regardless of threat
  CPU ≥ CPU_HIGH  (80%):  OVERLOADED → hard cap at Kyber-512 only

This directly answers the research question:
  "What is the security cost of constrained compute on Raspberry Pi?"

Publishable metrics logged to energy_decisions.csv:
  - cpu_at_decision   (CPU% at the moment of each security decision)
  - requested_param   (what the state machine wanted)
  - allowed_param     (what the energy gate actually permits)
  - was_capped        (True if gate overrode a higher param)
  - was_upgraded      (True if gate promoted to a higher param when CPU was free)
  - gate_reason       (human-readable explanation)

Thresholds are configurable via constructor kwargs for experiments.
"""

import os
import threading
import time
from datetime import datetime
from typing   import Optional

import psutil


# ─────────────────────────────────────────────────────────────
# Defaults  (override in constructor for experiments)
# ─────────────────────────────────────────────────────────────
CPU_LOW  = 30.0   # % — below this: free to proactively upgrade
CPU_MID  = 60.0   # % — above this: cap at Kyber-768
CPU_HIGH = 80.0   # % — above this: hard cap at Kyber-512

# Smoothing: use EMA of CPU to avoid spikes causing thrashing
CPU_EMA_ALPHA = 0.3   # weight on latest reading (0=never update, 1=no smoothing)

# Map: security level int → natural Kyber param (from state machine)
LEVEL_TO_PARAM = {0: 512, 1: 512, 2: 768, 3: 1024}  # overridden by Feature 2


class EnergyManager:
    """
    Thread-safe CPU-budget gate.
    Call gate(requested_param, security_level) to get the final param.
    """

    def __init__(self,
                 cpu_low:  float = CPU_LOW,
                 cpu_mid:  float = CPU_MID,
                 cpu_high: float = CPU_HIGH,
                 ema_alpha: float = CPU_EMA_ALPHA):
        self.cpu_low   = cpu_low
        self.cpu_mid   = cpu_mid
        self.cpu_high  = cpu_high
        self.ema_alpha = ema_alpha

        self._cpu_ema  = 0.0          # smoothed CPU estimate
        self._lock     = threading.Lock()
        self._proc     = psutil.Process(os.getpid())

        # Background sampler updates EMA every second
        self._running  = True
        threading.Thread(target=self._sampler, daemon=True,
                         name="EnergyMgr-Sampler").start()

        # Stats for logging
        self._total_decisions = 0
        self._cap_count       = 0
        self._upgrade_count   = 0

    def _sampler(self):
        """Update CPU EMA every second in background."""
        num_cores = max(1, psutil.cpu_count() or 1)
        while self._running:
            try:
                # Normalize across all CPU cores (0 - 100%)
                raw = self._proc.cpu_percent(interval=None) / num_cores
                with self._lock:
                    if self._cpu_ema == 0.0:
                        self._cpu_ema = raw
                    else:
                        self._cpu_ema = (self.ema_alpha * raw +
                                         (1 - self.ema_alpha) * self._cpu_ema)
            except Exception:
                pass
            time.sleep(1.0)

    def current_cpu(self) -> float:
        """Return current smoothed CPU estimate."""
        with self._lock:
            return round(self._cpu_ema, 2)

    def gate(self, requested_param: int, security_level: int) -> dict:
        """
        Apply CPU budget gate to a requested Kyber parameter.

        Parameters
        ----------
        requested_param  : int — Kyber param the state machine wants (512/768/1024)
        security_level   : int — current security level 0-3

        Returns dict:
            allowed_param   : int  — actual param to use
            cpu_at_decision : float
            was_capped      : bool
            was_upgraded    : bool
            gate_reason     : str
        """
        cpu = self.current_cpu()
        allowed   = requested_param
        capped    = False
        upgraded  = False
        reason    = "no gate applied"

        if cpu >= self.cpu_high:
            # OVERLOADED: hard cap at 512 regardless of threat
            if requested_param > 512:
                allowed  = 512
                capped   = True
                reason   = f"CPU={cpu:.1f}% >= {self.cpu_high}% — hard cap Kyber-512"
            else:
                reason   = f"CPU={cpu:.1f}% >= {self.cpu_high}% — already at 512, no change"

        elif cpu >= self.cpu_mid:
            # MODERATE LOAD: cap at 768
            if requested_param > 768:
                allowed  = 768
                capped   = True
                reason   = f"CPU={cpu:.1f}% >= {self.cpu_mid}% — cap at Kyber-768"
            else:
                reason   = f"CPU={cpu:.1f}% in mid range — no cap needed"

        elif cpu < self.cpu_low:
            # LOW LOAD: proactively upgrade if threat is high
            if security_level >= 2 and requested_param < 1024:
                allowed   = 1024
                upgraded  = True
                reason    = (f"CPU={cpu:.1f}% < {self.cpu_low}% and "
                             f"level={security_level} — proactive Kyber-1024")
            else:
                reason    = f"CPU={cpu:.1f}% low — no upgrade needed"

        else:
            reason = f"CPU={cpu:.1f}% normal range — no gate"

        with self._lock:
            self._total_decisions += 1
            if capped:    self._cap_count     += 1
            if upgraded:  self._upgrade_count += 1

        return {
            "allowed_param":   allowed,
            "cpu_at_decision": cpu,
            "was_capped":      capped,
            "was_upgraded":    upgraded,
            "gate_reason":     reason,
        }

    def stats(self) -> dict:
        with self._lock:
            return {
                "total_decisions": self._total_decisions,
                "cap_count":       self._cap_count,
                "upgrade_count":   self._upgrade_count,
                "current_cpu_ema": round(self._cpu_ema, 2),
            }

    def stop(self):
        self._running = False
