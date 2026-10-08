"""
ai/mission_phase.py
====================
Feature A — Mission-Phase Aware Security
==========================================
UAV missions have 4 distinct phases. Each phase carries a different
threat profile, compute budget, and required security level:

  PREFLIGHT  : UAV on ground, pre-mission checks.
               Full Kyber-1024 acceptable — battery full, time available.
               Highest security before sensitive mission data is loaded.

  INFLIGHT   : UAV airborne and operating.
               Kyber-512 preferred — battery conservation critical.
               IDS thresholds slightly relaxed (normal anomalies in flight).

  LANDING    : UAV descending / returning to base.
               Elevated security — landing is high-value interception window.
               Kyber-768 enforced regardless of IDS score.

  GROUNDIDLE : UAV landed, motors off, waiting.
               Minimal security — battery critical, low threat.
               Kyber-512, relaxed IDS thresholds.

Phase is inferred from telemetry fields already in every message:
  ALT=0  + BAT>50            → PREFLIGHT   (on ground, good battery)
  ALT>10                     → INFLIGHT
  ALT<10 + prev==INFLIGHT    → LANDING
  ALT=0  + BAT<30            → GROUNDIDLE  (battery drained)

Phase transition events are logged to mission_phase_events.csv.

Publishable metrics:
  - Kyber param per phase (paper table: phase vs latency vs security)
  - IDS threshold per phase (shows context-aware detection)
  - Phase transition count, dwell time per phase
  - Security overhead per phase (CPU%, latency)
"""

import threading
from datetime import datetime
from typing   import Optional
from enum     import Enum


class MissionPhase(Enum):
    PREFLIGHT  = "PREFLIGHT"
    INFLIGHT   = "INFLIGHT"
    LANDING    = "LANDING"
    GROUNDIDLE = "GROUNDIDLE"
    UNKNOWN    = "UNKNOWN"


# ── Phase policy: preferred Kyber param and IDS thresholds ────
PHASE_POLICY = {
    MissionPhase.PREFLIGHT: {
        "kyber_param":        1024,   # max security before mission
        "escalation_thresh":  0.35,   # aggressive IDS (low tolerance)
        "description":        "Pre-mission: max security, battery full",
    },
    MissionPhase.INFLIGHT: {
        "kyber_param":        512,    # battery conservation
        "escalation_thresh":  0.45,   # normal IDS thresholds
        "description":        "In-flight: fast crypto, balanced IDS",
    },
    MissionPhase.LANDING: {
        "kyber_param":        768,    # elevated — landing is high-value window
        "escalation_thresh":  0.38,   # slightly tighter IDS
        "description":        "Landing: elevated crypto, tighter IDS",
    },
    MissionPhase.GROUNDIDLE: {
        "kyber_param":        512,    # battery critical
        "escalation_thresh":  0.50,   # relaxed IDS
        "description":        "Ground idle: minimal overhead",
    },
    MissionPhase.UNKNOWN: {
        "kyber_param":        768,    # safe default
        "escalation_thresh":  0.40,
        "description":        "Unknown phase: conservative default",
    },
}


def infer_phase(altitude: float, battery: float,
                prev_phase: MissionPhase) -> MissionPhase:
    """
    Infer mission phase from telemetry values.
    Called by server every time a telemetry message is parsed.
    """
    if altitude > 10:
        return MissionPhase.INFLIGHT

    if altitude <= 1:
        if prev_phase == MissionPhase.INFLIGHT:
            return MissionPhase.LANDING
        if battery < 30:
            return MissionPhase.GROUNDIDLE
        if battery >= 50:
            return MissionPhase.PREFLIGHT
        return MissionPhase.GROUNDIDLE

    # ALT 1–10: could be low hover or short takeoff
    if prev_phase == MissionPhase.INFLIGHT:
        return MissionPhase.LANDING
    return MissionPhase.INFLIGHT


class MissionPhaseTracker:
    """
    Thread-safe per-client mission phase tracker.
    The server calls update() every telemetry message.
    Returns phase policy (Kyber param + IDS threshold) on each update.
    """

    def __init__(self):
        self._phases:       dict = {}   # client_addr → MissionPhase
        self._phase_start:  dict = {}   # client_addr → datetime when phase started
        self._dwell_times:  dict = {}   # client_addr → {phase: total_seconds}
        self._transitions:  dict = {}   # client_addr → list of (ts, from, to)
        self._lock = threading.Lock()

    def register(self, client_addr: tuple):
        with self._lock:
            self._phases[client_addr]      = MissionPhase.UNKNOWN
            self._phase_start[client_addr] = datetime.now()
            self._dwell_times[client_addr] = {p: 0.0 for p in MissionPhase}
            self._transitions[client_addr] = []

    def update(self, client_addr: tuple,
               altitude: float, battery: float) -> dict:
        """
        Update phase from telemetry and return current policy.
        Returns dict: phase, kyber_param, escalation_thresh,
                      phase_changed, dwell_in_prev_sec
        """
        with self._lock:
            prev   = self._phases.get(client_addr, MissionPhase.UNKNOWN)
            new    = infer_phase(altitude, battery, prev)
            now    = datetime.now()
            changed= (new != prev)
            dwell  = 0.0

            if changed:
                # Accumulate dwell time for the previous phase
                start  = self._phase_start.get(client_addr, now)
                dwell  = (now - start).total_seconds()
                dt_map = self._dwell_times.get(client_addr, {})
                dt_map[prev] = dt_map.get(prev, 0.0) + dwell
                self._dwell_times[client_addr] = dt_map
                self._phase_start[client_addr] = now
                self._phases[client_addr]      = new
                trans  = self._transitions.get(client_addr, [])
                trans.append((now.isoformat(), prev.value, new.value))
                self._transitions[client_addr] = trans

            policy = PHASE_POLICY[new]
            return {
                "phase":               new.value,
                "kyber_param":         policy["kyber_param"],
                "escalation_thresh":   policy["escalation_thresh"],
                "phase_changed":       changed,
                "prev_phase":          prev.value,
                "dwell_in_prev_sec":   dwell,
                "description":         policy["description"],
            }

    def get_phase(self, client_addr: tuple) -> MissionPhase:
        with self._lock:
            return self._phases.get(client_addr, MissionPhase.UNKNOWN)

    def get_policy(self, client_addr: tuple) -> dict:
        phase  = self.get_phase(client_addr)
        return PHASE_POLICY[phase]

    def summary(self, client_addr: tuple) -> dict:
        with self._lock:
            phase    = self._phases.get(client_addr, MissionPhase.UNKNOWN)
            dwell    = self._dwell_times.get(client_addr, {})
            trans    = self._transitions.get(client_addr, [])
            # Flush current phase dwell
            start    = self._phase_start.get(client_addr, datetime.now())
            curr_dwell = (datetime.now() - start).total_seconds()
            full_dwell = dict(dwell)
            full_dwell[phase] = full_dwell.get(phase, 0.0) + curr_dwell
        return {
            "final_phase":        phase.value,
            "num_transitions":    len(trans),
            "dwell_preflight_s":  round(full_dwell.get(MissionPhase.PREFLIGHT,  0.0), 2),
            "dwell_inflight_s":   round(full_dwell.get(MissionPhase.INFLIGHT,   0.0), 2),
            "dwell_landing_s":    round(full_dwell.get(MissionPhase.LANDING,    0.0), 2),
            "dwell_groundidle_s": round(full_dwell.get(MissionPhase.GROUNDIDLE, 0.0), 2),
            "transitions":        trans,
        }

    def remove(self, client_addr: tuple) -> dict:
        s = self.summary(client_addr)
        with self._lock:
            self._phases.pop(client_addr, None)
            self._phase_start.pop(client_addr, None)
            self._dwell_times.pop(client_addr, None)
            self._transitions.pop(client_addr, None)
        return s
