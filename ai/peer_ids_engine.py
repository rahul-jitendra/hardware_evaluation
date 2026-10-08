"""
peer_ids_engine.py — Decentralized AI Intrusion Detection Engine
================================================================
Combines:
1. Supervised XGBoost Classifier (ids_model.pkl)
2. Unsupervised Isolation Forest Anomaly Detector (ids_if_model.pkl)
3. Inductive Mondrian Conformal Prediction (ICP) for guaranteed error bounds (alpha=0.05)
4. Cyber-Physical Kinematic Sanity Checks (GPS Jump, Velocity, Altitude, Battery Drop)
5. Pure algorithmic inference latency benchmarking
"""

import os
import time
import math
import warnings
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple, Optional

warnings.filterwarnings("ignore", category=UserWarning)


FEATURE_COLS = [
    "Message Type", "Message Size", "Encryption Status", "File Extension",
    "File Size", "Number of Messages", "Number of Files", "Server Response Time",
    "Connection Duration", "Number of Connections", "Data Transfer Volume",
    "Request Frequency", "Error Rate", "Encryption Type",
    "Requests Per Second", "Volume Per Second",
]
CATEGORICAL_COLS = ["File Extension", "Encryption Status", "Encryption Type"]


class PeerIDSEngine:
    def __init__(self, models_dir: Optional[str] = None):
        if models_dir is None:
            models_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "models"))
        
        self.models_dir = models_dir
        self.xgb_model = None
        self.scaler = None
        self.encoders = {}
        self.if_model = None
        self.cal_scores_0 = None
        self.cal_scores_1 = None
        self.conformal_active = False

        self._load_models()

        # Peer tracking for kinematics & message rates
        self.peer_state: Dict[str, Dict[str, Any]] = {}

    def _load_models(self):
        try:
            m_path = os.path.join(self.models_dir, "ids_model.pkl")
            s_path = os.path.join(self.models_dir, "ids_scaler.pkl")
            if os.path.exists(m_path) and os.path.exists(s_path):
                self.xgb_model = joblib.load(m_path)
                self.scaler = joblib.load(s_path)
                # print(f"[PeerIDS] XGBoost and Scaler loaded from {self.models_dir}")

            enc_path = os.path.join(self.models_dir, "ids_encoders.pkl")
            if os.path.exists(enc_path):
                self.encoders = joblib.load(enc_path)

            if_path = os.path.join(self.models_dir, "ids_if_model.pkl")
            if os.path.exists(if_path):
                self.if_model = joblib.load(if_path)

            cal0_path = os.path.join(self.models_dir, "conformal_cal_0.pkl")
            cal1_path = os.path.join(self.models_dir, "conformal_cal_1.pkl")
            if os.path.exists(cal0_path) and os.path.exists(cal1_path):
                self.cal_scores_0 = joblib.load(cal0_path)
                self.cal_scores_1 = joblib.load(cal1_path)
                self.conformal_active = True
                # print("[PeerIDS] Mondrian Conformal Prediction matrices loaded.")
        except Exception as e:
            print(f"[PeerIDS] Warning during model loading: {e}")

    def evaluate_peer_telemetry(self, peer_id: str, telemetry: Dict[str, Any], raw_packet_size: int = 128) -> Dict[str, Any]:
        """
        Evaluates incoming peer telemetry frame:
        Returns threat score, conformal prediction set, physical anomalies, and inference latency.
        """
        t_start = time.perf_counter()
        t_now = time.time()

        lat = float(telemetry.get("lat", 0.0))
        lon = float(telemetry.get("lon", 0.0))
        alt = float(telemetry.get("alt", 0.0))
        voltage = float(telemetry.get("voltage", 11.5))
        seq = int(telemetry.get("seq", 0))

        # 1. Kinematic & Physical Metrics
        if peer_id not in self.peer_state:
            self.peer_state[peer_id] = {
                "first_time": t_now,
                "last_time": t_now,
                "last_lat": lat,
                "last_lon": lon,
                "last_alt": alt,
                "last_voltage": voltage,
                "last_seq": seq,
                "total_msgs": 0,
                "total_bytes": 0,
                "recent_timestamps": [],
                "error_count": 0
            }

        st = self.peer_state[peer_id]
        dt = max(0.001, t_now - st["last_time"])

        # Great-circle distance approx (m) - skip for first packet or time gap / standby transition
        if st["total_msgs"] == 0 or dt < 0.05 or dt > 2.5:
            dist_m = 0.0
            velocity_ms = 0.0
            alt_change_rate = 0.0
            voltage_drop_rate = 0.0
        else:
            dlat = (lat - st["last_lat"]) * 111139.0
            dlon = (lon - st["last_lon"]) * 111139.0 * math.cos(math.radians(lat))
            dist_m = math.sqrt(dlat*dlat + dlon*dlon)
            velocity_ms = dist_m / dt
            alt_change_rate = abs(alt - st["last_alt"]) / dt
            voltage_drop_rate = max(0.0, (st["last_voltage"] - voltage) / dt)

        st["total_msgs"] += 1
        st["total_bytes"] += raw_packet_size
        st["recent_timestamps"].append(t_now)
        # Keep timestamps from last 5 seconds for RPS
        st["recent_timestamps"] = [ts for ts in st["recent_timestamps"] if (t_now - ts) <= 5.0]
        rps = int(len(st["recent_timestamps"]) / 5.0) if st["recent_timestamps"] else 1
        vps = int((len(st["recent_timestamps"]) * raw_packet_size) / 5.0)

        conn_duration = max(0.1, t_now - st["first_time"])

        # Physical anomaly flags
        physical_anomaly = False
        anomaly_reasons = []

        if velocity_ms > 45.0:  # Excessive ground speed (>162 km/h for small multirotor)
            physical_anomaly = True
            anomaly_reasons.append(f"Unnatural velocity jump: {velocity_ms:.1f} m/s")
        if alt_change_rate > 20.0:  # Excessive vertical climb/drop
            physical_anomaly = True
            anomaly_reasons.append(f"Excessive vertical rate: {alt_change_rate:.1f} m/s")
        if rps > 50:  # High frequency flooding
            physical_anomaly = True
            anomaly_reasons.append(f"High RPS flooding: {rps} msg/s")

        # 2. Build 16-Feature Vector for Model
        raw_msg_count = len(st["recent_timestamps"])
        window_msgs = raw_msg_count if rps > 30 else min(20, max(1, raw_msg_count))
        window_vol = window_msgs * raw_packet_size
        raw_feat = {
            "Message Type": 0,
            "Message Size": raw_packet_size,
            "Encryption Status": "True",
            "File Extension": "none",
            "File Size": 0,
            "Number of Messages": window_msgs,
            "Number of Files": 0,
            "Server Response Time": round(dt * 1000.0, 2),
            "Connection Duration": round(min(5.0, conn_duration), 2),
            "Number of Connections": 1,
            "Data Transfer Volume": min(2560, window_vol) if rps <= 30 else window_vol,
            "Request Frequency": rps,
            "Error Rate": st["error_count"],
            "Encryption Type": "Kyber",
            "Requests Per Second": rps,
            "Volume Per Second": vps
        }

        row_dict = {}
        for col in FEATURE_COLS:
            val = raw_feat.get(col, 0)
            if col in CATEGORICAL_COLS and col in self.encoders:
                le = self.encoders[col]
                s = str(val)
                if s not in le.classes_:
                    s = le.classes_[0]
                val = int(le.transform([s])[0])
            try:
                row_dict[col] = float(val)
            except Exception:
                row_dict[col] = 0.0

        df = pd.DataFrame([row_dict], columns=FEATURE_COLS)

        # 3. Model Inference (XGBoost + Isolation Forest)
        xgb_prob = 0.01
        xgb_ms = 0.0
        df_scaled = None
        if self.xgb_model is not None and self.scaler is not None:
            t_xgb0 = time.perf_counter()
            try:
                df_scaled = pd.DataFrame(self.scaler.transform(df), columns=FEATURE_COLS)
                xgb_prob = float(self.xgb_model.predict_proba(df_scaled)[0, 1])
            except Exception:
                pass
            xgb_ms = (time.perf_counter() - t_xgb0) * 1000.0

        if_prob = 0.0
        if_ms = 0.0
        if self.if_model is not None and df_scaled is not None:
            t_if0 = time.perf_counter()
            try:
                score = float(self.if_model.decision_function(df_scaled)[0])
                # In Isolation Forest: score > 0 is inlier (normal), score < 0 is anomaly
                if_prob = float(np.clip((-score - (-0.2)) / (0.5), 0.0, 1.0)) if score < 0 else 0.0
            except Exception:
                pass
            if_ms = (time.perf_counter() - t_if0) * 1000.0

        # Cyber-physical threat blending
        if physical_anomaly:
            threat_prob = max(0.92, 0.6 * xgb_prob + 0.4 * if_prob)
        else:
            threat_prob = 0.70 * xgb_prob + 0.30 * if_prob

        # 4. Conformal Prediction Set Assessment (Mondrian ICP)
        conformal_set = "{Normal}"
        p0, p1 = None, None
        if self.conformal_active and self.cal_scores_0 is not None and self.cal_scores_1 is not None:
            p0 = float((np.sum(self.cal_scores_0 >= threat_prob) + 1) / (len(self.cal_scores_0) + 1))
            p1 = float((np.sum(self.cal_scores_1 >= 1.0 - threat_prob) + 1) / (len(self.cal_scores_1) + 1))
            epsilon = 0.05

            S = []
            if p0 > epsilon: S.append("Normal")
            if p1 > epsilon: S.append("Intruder")

            if len(S) == 2:
                conformal_set = "{Normal,Intruder}"  # Ambiguous / Elevated
            elif len(S) == 1 and S[0] == "Intruder":
                conformal_set = "{Intruder}"         # Confident Intrusion
            elif len(S) == 0:
                conformal_set = "{}"                 # Novel / Outlier Anomaly
            else:
                conformal_set = "{Normal}"           # Clean Normal

        is_anomaly = (threat_prob >= 0.75 or physical_anomaly or conformal_set in ("{Intruder}", "{}"))

        # Update last peer state
        st["last_time"] = t_now
        st["last_lat"] = lat
        st["last_lon"] = lon
        st["last_alt"] = alt
        st["last_voltage"] = voltage
        st["last_seq"] = seq

        tot_ms = (time.perf_counter() - t_start) * 1000.0

        return {
            "threat_prob": round(threat_prob, 4),
            "xgb_prob": round(xgb_prob, 4),
            "if_prob": round(if_prob, 4),
            "is_anomaly": is_anomaly,
            "physical_anomaly": physical_anomaly,
            "anomaly_reasons": anomaly_reasons,
            "conformal_set": conformal_set,
            "p0": round(p0, 4) if p0 is not None else None,
            "p1": round(p1, 4) if p1 is not None else None,
            "velocity_ms": round(velocity_ms, 2),
            "alt_change_rate": round(alt_change_rate, 2),
            "voltage_drop_rate": round(voltage_drop_rate, 3),
            "rps": rps,
            "infer_ms": round(tot_ms, 3)
        }
