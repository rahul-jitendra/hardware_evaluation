"""
ai/adaptive_security.py  — v5  (ALL 8 FEATURES)
=================================================
FEATURE 1  Hybrid ECC+Kyber KEM (trust-driven alpha)
FEATURE 2  Dynamic Kyber parameter escalation (512→768→1024)
FEATURE 3  Continuous EMA Trust Score per UAV
FEATURE 4  XGBoost + Isolation Forest Ensemble IDS
FEATURE 5  Energy-aware CPU gating
FEATURE A  Mission-phase aware security policy
FEATURE B  Anomaly velocity + acceleration early-warning
FEATURE E  Session resumption (lightweight reconnect)
"""

import os, queue, threading, time
from dataclasses import dataclass, field
from datetime    import datetime
from enum        import IntEnum
from typing      import Optional

import joblib
import numpy as np

# ─────────────────────────────────────────────────────────────
# Security Levels
# ─────────────────────────────────────────────────────────────

class SecurityLevel(IntEnum):
    NORMAL   = 0
    ELEVATED = 1
    HIGH     = 2
    CRITICAL = 3

LEVEL_LABELS = {
    SecurityLevel.NORMAL:   "NORMAL",
    SecurityLevel.ELEVATED: "ELEVATED",
    SecurityLevel.HIGH:     "HIGH",
    SecurityLevel.CRITICAL: "CRITICAL",
}

LEVEL_TO_KYBER_PARAM = {
    SecurityLevel.NORMAL:   512,
    SecurityLevel.ELEVATED: 768,
    SecurityLevel.HIGH:     1024,
    SecurityLevel.CRITICAL: 1024,
}

# Base escalation thresholds — overridden per-client by mission phase
BASE_ESCALATION_THRESHOLDS = {
    SecurityLevel.NORMAL:   0.40,
    SecurityLevel.ELEVATED: 0.65,
    SecurityLevel.HIGH:     0.85,
}
DEESCALATION_THRESHOLD = 0.25
DEESCALATION_WINDOWS   = 3

FEATURE_COLS = [
    "Message Type","Message Size","Encryption Status","File Extension",
    "File Size","Number of Messages","Number of Files","Server Response Time",
    "Connection Duration","Number of Connections","Data Transfer Volume",
    "Request Frequency","Error Rate","Encryption Type",
    "Requests Per Second","Volume Per Second",
]
CATEGORICAL_COLS = ["File Extension","Encryption Status","Encryption Type"]
ALPHA_XGB, ALPHA_IF = 0.70, 0.30


# ─────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────

@dataclass
class ClientSnapshot:
    client_addr:          tuple
    hostname:             str
    client_ip:            str
    encryption_type:      str
    message_type:         int
    message_size:         int
    file_size:            int
    file_extension:       Optional[str]
    num_messages:         int
    num_files:            int
    connection_duration:  float
    num_connections:      int
    data_transfer_volume: int
    request_frequency:    int
    error_rate:           int
    server_response_time: float
    requests_per_second:  int
    volume_per_second:    int
    snapshot_number:      int           = 0
    connect_time:         Optional[datetime] = None
    encryption_status:    bool          = True
    # Feature A: telemetry parsed values for mission phase
    altitude:             float         = 0.0
    battery:              float         = 100.0
    timestamp:            datetime      = field(default_factory=datetime.now)


@dataclass
class SecurityDecision:
    client_addr:          tuple
    hostname:             str
    new_level:            SecurityLevel
    previous_level:       SecurityLevel
    intruder_prob:        float
    ensemble_score:       float
    if_score:             float
    trust_score:          float
    alpha:                float
    kyber_param:          int
    kyber_param_previous: int
    cpu_at_decision:      float
    was_cpu_capped:       bool
    was_cpu_upgraded:     bool
    energy_gate_reason:   str
    # Feature A
    mission_phase:        str           = "UNKNOWN"
    phase_changed:        bool          = False
    phase_kyber_param:    int           = 512
    # Feature B
    velocity:             float         = 0.0
    acceleration:         float         = 0.0
    early_warning:        bool          = False
    velocity_warning_type:str           = "none"
    # Feature E
    session_resumed:      bool          = False
    ticket_saved_ms:      float         = 0.0
    action:               str           = ""
    force_rekey:          bool          = False
    terminate:            bool          = False
    rate_limit_rps:       Optional[int] = None
    time_to_detection_ms: Optional[float]= None
    snapshot_number:      int           = 0
    inference_time_ms:    float         = 0.0
    if_inference_time_ms: float         = 0.0
    total_inference_ms:   float         = 0.0
    encryption_type:      str           = ''
    conformal_p0:         Optional[float]= None
    conformal_p1:         Optional[float]= None
    conformal_set:        str           = ""
    timestamp:            datetime      = field(default_factory=datetime.now)


# ─────────────────────────────────────────────────────────────
class AdaptiveSecurityEngine:

    def __init__(self, model_path: str, scaler_path: str,
                 encoders_path: str = None, if_model_path: str = None,
                 disable_trust_alpha: bool = False,
                 disable_energy_gate: bool = False,
                 disable_mission_phase: bool = False,
                 disable_velocity: bool = False,
                 disable_rekey: bool = False):

        self._input  = queue.Queue()
        self._output = queue.Queue()
        self._levels:           dict = {}
        self._clean_counts:     dict = {}
        self._first_escalation: dict = {}
        self._kyber_params:     dict = {}
        self._lock    = threading.Lock()
        self._blacklist: set = set()
        self._bl_lock = threading.Lock()

        self.disable_trust_alpha   = disable_trust_alpha
        self.disable_energy_gate   = disable_energy_gate
        self.disable_mission_phase = disable_mission_phase
        self.disable_velocity      = disable_velocity
        self.disable_rekey         = disable_rekey

        # ── XGBoost ───────────────────────────────────────────
        self.model  = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        print(f"[ASE] XGBoost loaded: {model_path}")

        # ── Conformal Calibration Scores ──────────────────────
        cal_0_path = os.path.join(os.path.dirname(model_path), "conformal_cal_0.pkl")
        cal_1_path = os.path.join(os.path.dirname(model_path), "conformal_cal_1.pkl")
        if os.path.exists(cal_0_path) and os.path.exists(cal_1_path):
            self.cal_scores_0 = joblib.load(cal_0_path)
            self.cal_scores_1 = joblib.load(cal_1_path)
            self.conformal_active = True
            print(f"[ASE] Conformal Prediction active (loaded from: {cal_0_path} and {cal_1_path})")
        else:
            self.cal_scores_0 = None
            self.cal_scores_1 = None
            self.conformal_active = False
            print("[ASE] WARNING: Conformal calibration scores not found. Standard mode active.")

        # ── Encoders ──────────────────────────────────────────
        if encoders_path is None:
            encoders_path = os.path.join(os.path.dirname(model_path), "ids_encoders.pkl")
        if os.path.exists(encoders_path):
            self.encoders = joblib.load(encoders_path)
            print(f"[ASE] Encoders loaded: {encoders_path}")
        else:
            self.encoders = {}
            print("[ASE] WARNING: ids_encoders.pkl not found.")

        # ── Isolation Forest (F4) ─────────────────────────────
        if if_model_path is None:
            if_model_path = os.path.join(os.path.dirname(model_path), "ids_if_model.pkl")
        if os.path.exists(if_model_path):
            self.if_model = joblib.load(if_model_path)
            self._if_min  = -0.5
            self._if_max  =  0.5
            print(f"[ASE] Isolation Forest loaded: {if_model_path}")
        else:
            self.if_model = None
            print("[ASE] Isolation Forest not found — XGBoost-only mode.")

        # ── Trust Manager (F3) ────────────────────────────────
        from ai.trust_manager import TrustManager
        self.trust_mgr = TrustManager()
        print("[ASE] Trust Manager active.")

        # ── Energy Manager (F5) ───────────────────────────────
        from ai.energy_manager import EnergyManager
        self.energy_mgr = EnergyManager()
        print("[ASE] Energy Manager active.")

        # ── Mission Phase Tracker (Feature A) ─────────────────
        from ai.mission_phase import MissionPhaseTracker
        self.phase_tracker = MissionPhaseTracker()
        print("[ASE] Mission Phase Tracker active.")

        # ── Anomaly Velocity Tracker (Feature B) ──────────────
        from ai.anomaly_velocity import AnomalyVelocityTracker
        self.velocity_tracker = AnomalyVelocityTracker()
        print("[ASE] Anomaly Velocity Tracker active.")

        # ── Session Resumption Manager (Feature E) ────────────
        from ai.session_resumption import SessionTicketManager
        self.session_mgr = SessionTicketManager()
        print("[ASE] Session Resumption Manager active.")

        self._running = True
        threading.Thread(target=self._worker, daemon=True, name="ASE-Worker").start()
        print("[ASE] Engine v5 — F1 F2 F3 F4 F5 FA FB FE — all active.\n")

    # ── Public API ─────────────────────────────────────────────

    def submit(self, snap: ClientSnapshot):
        self._input.put_nowait(snap)

    def poll(self) -> Optional[SecurityDecision]:
        try:    return self._output.get_nowait()
        except: return None

    def get_level(self, addr) -> SecurityLevel:
        with self._lock: return self._levels.get(addr, SecurityLevel.NORMAL)

    def get_kyber_param(self, addr) -> int:
        with self._lock: return self._kyber_params.get(addr, 512)

    def get_session_mgr(self):
        return self.session_mgr

    def is_blacklisted(self, ip: str) -> bool:
        if ip == "127.0.0.1": return False
        with self._bl_lock: return ip in self._blacklist

    def register_client(self, addr, hostname, connect_time):
        self.trust_mgr.register(addr, hostname, connect_time)
        self.phase_tracker.register(addr)
        self.velocity_tracker.register(addr, hostname, connect_time)
        with self._lock:
            self._kyber_params[addr] = 512

    def remove_client(self, addr):
        with self._lock:
            self._levels.pop(addr, None)
            self._clean_counts.pop(addr, None)
            self._first_escalation.pop(addr, None)
            self._kyber_params.pop(addr, None)
        trust_summary  = self.trust_mgr.remove(addr)
        phase_summary  = self.phase_tracker.remove(addr)
        vel_summary    = self.velocity_tracker.remove(addr)
        return {
            "trust":   trust_summary,
            "phase":   phase_summary,
            "velocity":vel_summary,
        }

    def stop(self): self._running = False

    # ── Feature vector ────────────────────────────────────────

    def _to_vector(self, snap: ClientSnapshot) -> np.ndarray:
        raw = {
            "Message Type":         snap.message_type,
            "Message Size":         snap.message_size,
            "Encryption Status":    str(snap.encryption_status),
            "File Extension":       snap.file_extension or "none",
            "File Size":            snap.file_size,
            "Number of Messages":   snap.num_messages,
            "Number of Files":      snap.num_files,
            "Server Response Time": snap.server_response_time,
            "Connection Duration":  snap.connection_duration,
            "Number of Connections":snap.num_connections,
            "Data Transfer Volume": snap.data_transfer_volume,
            "Request Frequency":    snap.request_frequency,
            "Error Rate":           snap.error_rate,
            "Encryption Type":      snap.encryption_type,
            "Requests Per Second":  snap.requests_per_second,
            "Volume Per Second":    snap.volume_per_second,
        }
        row = []
        for col in FEATURE_COLS:
            val = raw.get(col, 0)
            if col in CATEGORICAL_COLS and col in self.encoders:
                le = self.encoders[col]; s = str(val)
                if s not in le.classes_: s = le.classes_[0]
                val = int(le.transform([s])[0])
            try:    row.append(float(val))
            except: row.append(0.0)
        return np.array(row, dtype=np.float32).reshape(1, -1)

    # ── Worker ────────────────────────────────────────────────

    def _worker(self):
        while self._running:
            try:
                snap = self._input.get(timeout=1.0)
                self._evaluate(snap)
            except queue.Empty: continue
            except Exception as e:
                print(f"[ASE] Worker error: {e}")

    def _evaluate(self, snap: ClientSnapshot):
        import psutil as _ps, os as _os

        # ── Blacklisted fast-path ─────────────────────────────
        if self.is_blacklisted(snap.client_ip):
            trust = self.trust_mgr.get_trust(snap.client_addr)
            d = SecurityDecision(
                client_addr=snap.client_addr, hostname=snap.hostname,
                new_level=SecurityLevel.CRITICAL, previous_level=SecurityLevel.CRITICAL,
                intruder_prob=1.0, ensemble_score=1.0, if_score=1.0,
                trust_score=trust, alpha=1.0,
                kyber_param=1024, kyber_param_previous=1024,
                cpu_at_decision=self.energy_mgr.current_cpu(),
                was_cpu_capped=False, was_cpu_upgraded=False,
                energy_gate_reason="blacklisted",
                action="Blacklisted IP - auto-terminate", terminate=True,
                encryption_type=snap.encryption_type,
                snapshot_number=snap.snapshot_number)
            self._output.put(d); self._write_logs(d, snap); return

        fv   = self._to_vector(snap)
        fv_s = self.scaler.transform(fv)

        # ── XGBoost (F4) ──────────────────────────────────────
        t0       = time.perf_counter()
        xgb_prob = float(self.model.predict_proba(fv_s)[0, 1])
        xgb_ms   = (time.perf_counter() - t0) * 1000

        # ── Isolation Forest (F4) ─────────────────────────────
        if_prob = 0.0; if_ms = 0.0
        if self.if_model is not None:
            t0    = time.perf_counter()
            score = float(self.if_model.decision_function(fv_s)[0])
            if_ms = (time.perf_counter() - t0) * 1000
            self._if_min = min(self._if_min, score)
            self._if_max = max(self._if_max, score)
            anom  = -score
            mn, mx = self._if_min, self._if_max
            if_prob = float(np.clip((anom-(-mx))/((-mn)-(-mx)+1e-9), 0, 1)) if mx > mn else 0.0

        ens_score = ALPHA_XGB * xgb_prob + ALPHA_IF * if_prob
        total_ms  = xgb_ms + if_ms

        # ── Trust (F3) ────────────────────────────────────────
        trust = self.trust_mgr.update(snap.client_addr, ens_score)
        from key_encapsulation.hybrid_kem import trust_to_alpha
        if self.disable_trust_alpha:
            alpha = 0.5
        else:
            alpha = trust_to_alpha(trust)
        self._log_trust(snap, trust, alpha, xgb_prob, if_prob, ens_score)

        # ── Mission Phase (FA) ────────────────────────────────
        phase_info = self.phase_tracker.update(
            snap.client_addr, snap.altitude, snap.battery)
        if self.disable_mission_phase:
            phase_name         = "UNKNOWN"
            phase_kyber_param  = 512
            phase_thresh       = None
            phase_changed      = False
        else:
            phase_name         = phase_info["phase"]
            phase_kyber_param  = phase_info["kyber_param"]
            phase_thresh       = phase_info["escalation_thresh"]
            phase_changed      = phase_info["phase_changed"]

        # Log phase change event
        if phase_changed:
            self._log_phase_event(snap, phase_info)

        # ── Anomaly Velocity (FB) ─────────────────────────────
        vel_info = self.velocity_tracker.update(
            snap.client_addr, ens_score,
            snap.connect_time or datetime.now())
        if self.disable_velocity:
            velocity     = 0.0
            acceleration = 0.0
            early_warning= False
            warn_type    = "none"
        else:
            velocity     = vel_info["velocity"]
            acceleration = vel_info["acceleration"]
            early_warning= vel_info["early_warning"]
            warn_type    = vel_info["warning_type"]

        # ── Conformal Prediction p-values and set ──────────────
        p_0 = None
        p_1 = None
        conformal_set_str = "N/A"
        if self.conformal_active:
            # Mondrian p-values
            p_0 = float((np.sum(self.cal_scores_0 >= ens_score) + 1) / (len(self.cal_scores_0) + 1))
            p_1 = float((np.sum(self.cal_scores_1 >= 1.0 - ens_score) + 1) / (len(self.cal_scores_1) + 1))

            epsilon = 0.05
            S = []
            if p_0 > epsilon: S.append(0)
            if p_1 > epsilon: S.append(1)

            # Map set to string representation (e.g. "{Normal}", "{Intruder}", "{Normal,Intruder}", "{}")
            if len(S) == 2:
                conformal_set_str = "{Normal,Intruder}"
                target_level = SecurityLevel.ELEVATED
                verdict = "AMBIGUOUS"
            elif len(S) == 1 and S[0] == 1:
                conformal_set_str = "{Intruder}"
                target_level = SecurityLevel.CRITICAL
                verdict = "INTRUDER"
            elif len(S) == 0:
                conformal_set_str = "{}"
                target_level = SecurityLevel.HIGH
                verdict = "NOVEL"
            else:
                conformal_set_str = "{Normal}"
                target_level = SecurityLevel.NORMAL
                verdict = "NORMAL"

        # ── State machine (phase-aware thresholds) ────────────
        with self._lock:
            prev        = self._levels.get(snap.client_addr, SecurityLevel.NORMAL)
            clean_count = self._clean_counts.get(snap.client_addr, 0)
            already_esc = self._first_escalation.get(snap.client_addr, False)
            prev_param  = self._kyber_params.get(snap.client_addr, 512)

            # Feature B: if early warning, reduce de-escalation grace
            eff_deesc_windows = 1 if early_warning else DEESCALATION_WINDOWS

            if self.conformal_active:
                new_level, action, rekey, terminate, rate_limit, clean_count = \
                    self._conformal_state_machine(prev, target_level, verdict, p_0, p_1,
                                                 clean_count, eff_deesc_windows)
            else:
                new_level, action, rekey, terminate, rate_limit, clean_count = \
                    self._state_machine(prev, ens_score, clean_count,
                                        phase_thresh, eff_deesc_windows)
            if self.disable_rekey:
                rekey = False

            # Feature 2: level → Kyber param
            desired_param = LEVEL_TO_KYBER_PARAM[new_level]

            # Feature A: phase may override Kyber param upward
            # (e.g. PREFLIGHT forces 1024 regardless of threat level)
            if phase_kyber_param > desired_param:
                desired_param = phase_kyber_param
                action = f"{action}  [Phase:{phase_name} → Kyber-{phase_kyber_param}]"

            self._levels[snap.client_addr]       = new_level
            self._clean_counts[snap.client_addr] = clean_count

            ttd = None
            if new_level > SecurityLevel.NORMAL and not already_esc:
                if snap.connect_time:
                    ttd = (datetime.now()-snap.connect_time).total_seconds()*1000
                self._first_escalation[snap.client_addr] = True

        # Feature B: early warning action note
        if early_warning:
            action = f"{action}  [EarlyWarn:{warn_type} vel={velocity:.3f}]"

        # ── Energy Gate (F5) ──────────────────────────────────
        if self.disable_energy_gate:
            gate = {
                "allowed_param": desired_param,
                "gate_reason": "gating disabled",
                "was_capped": False,
                "was_upgraded": False,
                "cpu_at_decision": self.energy_mgr.current_cpu()
            }
        else:
            gate = self.energy_mgr.gate(desired_param, int(new_level))
        final_param = gate["allowed_param"]

        if final_param != prev_param:
            rekey = True
            action = (f"{action}  Kyber {prev_param}->{final_param}"
                      f" [{gate['gate_reason']}]")
        elif rekey:
            pass  # rekey flag stays True

        with self._lock:
            self._kyber_params[snap.client_addr] = final_param

        self._log_energy(snap, desired_param, final_param, gate, new_level)

        # Feature B: log velocity snapshot every evaluation
        self._log_velocity(snap, ens_score, vel_info, snap.connection_duration)

        if terminate:
            with self._bl_lock: self._blacklist.add(snap.client_ip)
            # Feature E: revoke session ticket on termination
            self.session_mgr.revoke_client(snap.hostname)

        decision = SecurityDecision(
            client_addr          = snap.client_addr,
            hostname             = snap.hostname,
            new_level            = new_level,
            previous_level       = prev,
            intruder_prob        = xgb_prob,
            ensemble_score       = round(ens_score, 6),
            if_score             = round(if_prob, 6),
            trust_score          = round(trust, 6),
            alpha                = round(alpha, 4),
            kyber_param          = final_param,
            kyber_param_previous = prev_param,
            cpu_at_decision      = gate["cpu_at_decision"],
            was_cpu_capped       = gate["was_capped"],
            was_cpu_upgraded     = gate["was_upgraded"],
            energy_gate_reason   = gate["gate_reason"],
            mission_phase        = phase_name,
            phase_changed        = phase_changed,
            phase_kyber_param    = phase_kyber_param,
            velocity             = round(velocity, 6),
            acceleration         = round(acceleration, 6),
            early_warning        = early_warning,
            velocity_warning_type= warn_type,
            action               = action,
            force_rekey          = rekey,
            terminate            = terminate,
            rate_limit_rps       = rate_limit,
            time_to_detection_ms = ttd,
            snapshot_number      = snap.snapshot_number,
            inference_time_ms    = round(xgb_ms, 4),
            if_inference_time_ms = round(if_ms, 4),
            total_inference_ms   = round(total_ms, 4),
            encryption_type      = snap.encryption_type,
            conformal_p0         = p_0,
            conformal_p1         = p_1,
            conformal_set        = conformal_set_str,
        )
        self._output.put(decision)
        self._write_logs(decision, snap)

        try:
            from logger.metrics_logger import log_hardware_metrics
            proc = _ps.Process(_os.getpid())
            log_hardware_metrics(
                client_id=snap.hostname, event_type='snapshot',
                cpu_usage_pct=gate["cpu_at_decision"],
                memory_usage_mb=proc.memory_info().rss/(1024*1024),
                ai_inference_time_ms=total_ms,
                encryption_type=snap.encryption_type)
        except: pass

        if (new_level != prev or final_param != prev_param
                or early_warning or phase_changed):
            arr = "UP" if new_level >= prev else "DOWN"
            ew  = " [EARLY-WARN]" if early_warning else ""
            ph  = f" [PHASE:{phase_name}]" if phase_changed else ""
            print(f"[ASE] {arr} {snap.hostname} | "
                  f"{LEVEL_LABELS[prev]}->{LEVEL_LABELS[new_level]} | "
                  f"Kyber {prev_param}->{final_param} | "
                  f"ens={ens_score:.3f} vel={velocity:+.3f} "
                  f"trust={trust:.3f} cpu={gate['cpu_at_decision']:.1f}%"
                  + ew + ph)

    def _conformal_state_machine(self, prev, target_level, verdict, p_0, p_1, clean_count, deesc_windows):
        rekey = False; terminate = False; rate_limit = None
        if deesc_windows is None:
            deesc_windows = DEESCALATION_WINDOWS

        # If target conformal level is higher than prev, escalate immediately!
        if target_level > prev:
            new_level = target_level
            clean_count = 0
            if new_level == SecurityLevel.ELEVATED:
                action = f"Conformal CP ({verdict}): Suspicious (p0={p_0:.3f}, p1={p_1:.3f}). Rate-limit 50. Kyber-768."
                rate_limit = 50
            elif new_level == SecurityLevel.HIGH:
                action = f"Conformal CP ({verdict}): Novel anomaly (p0={p_0:.3f}, p1={p_1:.3f}). Kyber-1024. Rate-limit 10."
                rekey = True
                rate_limit = 10
            elif new_level == SecurityLevel.CRITICAL:
                action = f"Conformal CP ({verdict}): Confirmed Intruder (p0={p_0:.3f}, p1={p_1:.3f}). Kyber-1024. Terminate."
                terminate = True
            return new_level, action, rekey, terminate, rate_limit, clean_count

        # If target level is lower than prev, de-escalate with grace period
        if target_level < prev:
            clean_count += 1
            if clean_count >= deesc_windows:
                new_level = SecurityLevel(int(prev) - 1)
                clean_count = 0
                action = f"Conformal CP (Reduced Threat): De-escalate to {LEVEL_LABELS[new_level]}."
                rekey = True
                if new_level == SecurityLevel.ELEVATED: rate_limit = 50
                return new_level, action, rekey, terminate, rate_limit, clean_count
            else:
                action = f"Conformal CP ({LEVEL_LABELS[target_level]}, cleaning): Stays {LEVEL_LABELS[prev]}."
                if prev == SecurityLevel.ELEVATED: rate_limit = 50
                elif prev == SecurityLevel.HIGH: rate_limit = 10
                return prev, action, rekey, terminate, rate_limit, clean_count

        # Target level is equal to prev
        action = f"Conformal CP ({verdict}): Stays {LEVEL_LABELS[prev]}."
        if prev == SecurityLevel.ELEVATED: rate_limit = 50
        elif prev == SecurityLevel.HIGH: rate_limit = 10
        return prev, action, rekey, terminate, rate_limit, clean_count

    def _state_machine(self, prev, prob, clean_count,
                       escalation_thresh_override=None,
                       deesc_windows=None):
        """Phase-aware state machine with velocity-adjusted de-escalation."""
        rekey=False; terminate=False; rate_limit=None
        if deesc_windows is None:
            deesc_windows = DEESCALATION_WINDOWS

        if prev < SecurityLevel.CRITICAL:
            # Use phase-overridden threshold for NORMAL level if provided
            if escalation_thresh_override and prev == SecurityLevel.NORMAL:
                thresh = escalation_thresh_override
            else:
                thresh = BASE_ESCALATION_THRESHOLDS[prev]

            if prob > thresh:
                new_level = SecurityLevel(int(prev)+1); clean_count=0
                if new_level == SecurityLevel.ELEVATED:
                    action=f"Suspicious P={prob:.3f}. Rate-limit 50. Kyber-768."; rate_limit=50
                elif new_level == SecurityLevel.HIGH:
                    action=f"High P={prob:.3f}. Kyber-1024. Rate-limit 10."; rekey=True; rate_limit=10
                elif new_level == SecurityLevel.CRITICAL:
                    action=f"CRITICAL P={prob:.3f}. Kyber-1024. Terminate."; terminate=True
                return new_level, action, rekey, terminate, rate_limit, clean_count

        if prob < DEESCALATION_THRESHOLD: clean_count+=1
        else: clean_count=0

        if clean_count >= deesc_windows and prev > SecurityLevel.NORMAL:
            new_level=SecurityLevel(int(prev)-1); clean_count=0
            action=f"Threat reduced P={prob:.3f}. De-escalate."
            rekey = True
            if new_level==SecurityLevel.ELEVATED: rate_limit=50
            return new_level, action, rekey, terminate, rate_limit, clean_count

        action=f"No change P={prob:.3f}. Stays {LEVEL_LABELS[prev]}."
        if prev==SecurityLevel.ELEVATED: rate_limit=50
        elif prev==SecurityLevel.HIGH:   rate_limit=10
        return prev, action, rekey, terminate, rate_limit, clean_count

    def _write_logs(self, d: SecurityDecision, snap: ClientSnapshot):
        try:
            from logger.metrics_logger import log_security_decision_extended
            log_security_decision_extended(
                client_id=d.hostname, client_ip=snap.client_ip,
                encryption_type=d.encryption_type,
                previous_level=LEVEL_LABELS[d.previous_level],
                new_level=LEVEL_LABELS[d.new_level],
                xgb_prob=d.intruder_prob, if_score=d.if_score,
                ensemble_score=d.ensemble_score, trust_score=d.trust_score,
                alpha=d.alpha,
                kyber_param=d.kyber_param, kyber_param_previous=d.kyber_param_previous,
                cpu_at_decision=d.cpu_at_decision,
                was_cpu_capped=d.was_cpu_capped, was_cpu_upgraded=d.was_cpu_upgraded,
                energy_gate_reason=d.energy_gate_reason,
                mission_phase=d.mission_phase, phase_changed=d.phase_changed,
                velocity=d.velocity, acceleration=d.acceleration,
                early_warning=d.early_warning,
                velocity_warning_type=d.velocity_warning_type,
                action=d.action, force_rekey=d.force_rekey,
                terminated=d.terminate, rate_limit_rps=d.rate_limit_rps,
                time_to_detection_ms=d.time_to_detection_ms,
                snapshot_window=d.snapshot_number,
                xgb_inference_ms=d.inference_time_ms,
                if_inference_ms=d.if_inference_time_ms,
                total_inference_ms=d.total_inference_ms,
                conformal_p0=d.conformal_p0,
                conformal_p1=d.conformal_p1,
                conformal_set=d.conformal_set)
        except Exception as e:
            print(f"[ASE] Log error: {e}")

    def _log_trust(self, snap, trust, alpha, xgb_prob, if_prob, ens_score):
        try:
            from logger.metrics_logger import log_trust_trajectory
            log_trust_trajectory(
                client_id=snap.hostname, client_ip=snap.client_ip,
                encryption_type=snap.encryption_type,
                snapshot_number=snap.snapshot_number,
                trust_score=trust, alpha=alpha,
                xgb_prob=xgb_prob, if_prob=if_prob,
                ensemble_score=ens_score,
                connection_duration_sec=snap.connection_duration)
        except Exception as e:
            print(f"[ASE] Trust log error: {e}")

    def _log_energy(self, snap, desired_param, final_param, gate, new_level):
        try:
            from logger.metrics_logger import log_energy_decision
            log_energy_decision(
                client_id=snap.hostname, client_ip=snap.client_ip,
                encryption_type=snap.encryption_type,
                snapshot_number=snap.snapshot_number,
                security_level=LEVEL_LABELS[new_level],
                desired_kyber_param=desired_param,
                allowed_kyber_param=final_param,
                cpu_at_decision=gate["cpu_at_decision"],
                was_capped=gate["was_capped"],
                was_upgraded=gate["was_upgraded"],
                gate_reason=gate["gate_reason"],
                connection_duration_sec=snap.connection_duration)
        except Exception as e:
            print(f"[ASE] Energy log error: {e}")

    def _log_phase_event(self, snap, phase_info):
        try:
            from logger.metrics_logger import log_mission_phase_event
            log_mission_phase_event(
                client_id=snap.hostname, client_ip=snap.client_ip,
                encryption_type=snap.encryption_type,
                prev_phase=phase_info["prev_phase"],
                new_phase=phase_info["phase"],
                phase_kyber_param=phase_info["kyber_param"],
                phase_escalation_thresh=phase_info["escalation_thresh"],
                dwell_in_prev_sec=phase_info["dwell_in_prev_sec"],
                altitude=snap.altitude, battery=snap.battery,
                connection_duration_sec=snap.connection_duration)
        except Exception as e:
            print(f"[ASE] Phase log error: {e}")

    def _log_velocity(self, snap, ensemble_score, vel_info, connection_duration):
        try:
            from logger.metrics_logger import log_anomaly_velocity
            log_anomaly_velocity(
                client_id=snap.hostname, client_ip=snap.client_ip,
                encryption_type=snap.encryption_type,
                snapshot_number=snap.snapshot_number,
                ensemble_score=ensemble_score,
                velocity=vel_info.get("velocity", 0.0),
                acceleration=vel_info.get("acceleration", 0.0),
                early_warning=vel_info.get("early_warning", False),
                warning_type=vel_info.get("warning_type", "none"),
                trend_rising=vel_info.get("trend_rising", False),
                velocity_ttd_ms=vel_info.get("velocity_ttd_ms"),
                connection_duration_sec=connection_duration,
                intruder_flag=0)
        except Exception as e:
            print(f"[ASE] Velocity log error: {e}")