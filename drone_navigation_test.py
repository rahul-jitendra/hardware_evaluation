"""
drone_navigation_test.py — Autonomous 4-Waypoint Drone Navigation & Landing (ArduCopter / Cube Orange)
=========================================================================================================
What was fixed compared to the previous version
-----------------------------------------------
The old script depended on an external `mavlink_interface` module and only "fired and forgot" commands,
so when the flight controller refused to arm (pre-arm check failed, wrong mode, no GPS, ...) the script
never noticed, kept printing "climbing", and the only visible effect was the mode change.

This version is self-contained (only needs `pymavlink`) and follows the sequence ArduCopter requires:

  1. Connect, wait for the autopilot HEARTBEAT, learn target system/component.
  2. Send our own 1 Hz GCS heartbeat continuously (needed if FS_GCS_ENABLE is on) and request telemetry streams.
  3. Wait for a 3D GPS fix + enough satellites.
  4. Switch to GUIDED and VERIFY the mode really changed (from the heartbeat).
  5. ARM and VERIFY the vehicle is really armed (retries; prints every "PreArm:" message from the FCU).
  6. Immediately send NAV_TAKEOFF (must happen within ~10 s of arming, otherwise ArduCopter auto-disarms).
  7. Fly each waypoint with SET_POSITION_TARGET_GLOBAL_INT (re-sent every second), check distance + altitude.
  8. At waypoint 4 switch to LAND and wait for the FCU to disarm on touchdown.

Safety
------
  * Type 'b' + Enter at any time -> LAND on the spot.  Ctrl+C -> LAND on the spot.
  * If the pilot flips the mode switch (or a failsafe changes the mode) the script stops commanding the
    vehicle immediately - it never fights the pilot.
  * If arming / takeoff / a waypoint fails, the script does NOT silently continue; it lands or aborts.

Usage examples
--------------
  Simulation only (no hardware):     python drone_navigation_test.py
  Cube Orange over USB (Windows):    python drone_navigation_test.py --mavlink COM3 --mavlink-baud 115200
  Cube Orange over USB (Linux):      python drone_navigation_test.py --mavlink /dev/ttyACM0
  Telemetry radio / Pi UART:         python drone_navigation_test.py --mavlink /dev/ttyAMA0 --mavlink-baud 57600
  SITL / MAVProxy output:            python drone_navigation_test.py --mavlink udp:127.0.0.1:14550
  Custom waypoints:                  --wp1 "lat,lon,alt" --wp2 ... --wp3 ... --wp4 ...   (or --interactive)

Requires:  pip install pymavlink
"""

import sys
import time
import math
import argparse
import threading
from collections import deque
from typing import List, Dict, Any, Optional

try:
    from pymavlink import mavutil
    PYMAVLINK_AVAILABLE = True
except ImportError:  # pragma: no cover
    mavutil = None
    PYMAVLINK_AVAILABLE = False


# ==============================================================================
# 1. USER-CONFIGURABLE 4 WAYPOINTS (EDIT YOUR COORDINATES HERE)
# ==============================================================================
# Format: {"name": "Label", "lat": Latitude, "lon": Longitude, "alt": Altitude_Meters (relative to home)}
DEFAULT_WAYPOINTS: List[Dict[str, Any]] = [
    {"name": "Waypoint 1", "lat": 16.792406, "lon": 80.819767, "alt": 3.0},
    {"name": "Waypoint 2", "lat": 16.792440, "lon": 80.820356, "alt": 3.0},
    {"name": "Waypoint 3", "lat": 16.792455, "lon": 80.821035, "alt": 3.0},
    {"name": "Waypoint 4 (Final Landing)", "lat": 16.792820, "lon": 80.820500, "alt": 3.0},
]

MAV_RESULT_NAMES = {0: "ACCEPTED", 1: "TEMPORARILY_REJECTED", 2: "DENIED", 3: "UNSUPPORTED",
                    4: "FAILED", 5: "IN_PROGRESS", 6: "CANCELLED"}


# ==============================================================================
# 2. GEODETIC DISTANCE UTILITIES (HAVERSINE)
# ==============================================================================
def haversine_distance_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Ground distance in meters between two GPS coordinates."""
    R = 6371000.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlmb / 2.0) ** 2
    return R * 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))


class MissionAbort(Exception):
    """Raised to leave the mission flow (emergency land, pilot took over, failure...)."""


# ==============================================================================
# 3A. REAL VEHICLE: ARDUCOPTER OVER MAVLINK (pymavlink)
# ==============================================================================
class MavlinkVehicle:
    is_hardware = True
    # Multirotor-ish MAV_TYPEs: quad, coax, heli, hexa, octo, tri, dodeca, deca
    MULTIROTOR_TYPES = {2, 3, 4, 13, 14, 15, 29, 35}

    def __init__(self, conn: str, baud: int):
        self.conn = conn
        self.baud = baud
        self.master = None
        self.hb_type = None
        self._send_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._acks: Dict[int, int] = {}
        self._last_rx = 0.0
        self.statustexts = deque(maxlen=50)
        self._t: Dict[str, Any] = dict(lat=None, lon=None, alt=0.0, voltage=0.0, mode="UNKNOWN",
                                       armed=False, fix=0, sats=0)

    # ---------------------------------------------------------------- connection
    def connect(self, timeout: float = 30.0) -> bool:
        if not PYMAVLINK_AVAILABLE:
            print("[!] pymavlink is not installed.  Run:  pip install pymavlink")
            return False

        print(f"[*] Connecting to flight controller on {self.conn} (baud {self.baud}) ...")
        try:
            self.master = mavutil.mavlink_connection(self.conn, baud=self.baud,
                                                     source_system=255, source_component=190)
        except Exception as e:
            print(f"[!] Could not open {self.conn}: {e}")
            print("    - Close Mission Planner / QGroundControl / MAVProxy if they are using the same COM port.")
            return False

        deadline = time.time() + timeout
        hb = None
        while time.time() < deadline:
            m = self.master.recv_match(type="HEARTBEAT", blocking=True, timeout=1.0)
            if m is None:
                continue
            if m.autopilot == mavutil.mavlink.MAV_AUTOPILOT_INVALID or m.type == mavutil.mavlink.MAV_TYPE_GCS:
                continue
            hb = m
            break
        if hb is None:
            print(f"[!] No autopilot heartbeat within {timeout:.0f}s. Check port, baud rate and SERIALx_PROTOCOL.")
            return False

        if hb.autopilot != mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA:
            print("[!] Autopilot is not ArduPilot (PX4 detected?). This script uses ArduCopter modes "
                  "(GUIDED / LAND) and will not work on PX4.")
            return False
        if hb.type not in self.MULTIROTOR_TYPES:
            print(f"[!] Vehicle type {hb.type} is not a multirotor (ArduCopter expected).")
            return False

        self.hb_type = hb.type
        self.master.target_system = hb.get_srcSystem()
        self.master.target_component = hb.get_srcComponent()
        self._last_rx = time.time()
        print(f"[+] Heartbeat received from system {self.master.target_system}, "
              f"component {self.master.target_component}  (ArduCopter).")

        self._thread = threading.Thread(target=self._reader, daemon=True)
        self._thread.start()
        self._request_streams()
        return True

    def close(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.5)
        try:
            if self.master:
                self.master.close()
        except Exception:
            pass

    # ---------------------------------------------------------------- low level I/O
    def _send(self, fn):
        with self._send_lock:
            fn()

    def _request_streams(self):
        ts, tc = self.master.target_system, self.master.target_component
        # Modern way: per-message intervals (microseconds)
        for msg_id, hz in ((1, 2), (24, 2), (33, 5), (74, 2)):  # SYS_STATUS, GPS_RAW_INT, GLOBAL_POSITION_INT, VFR_HUD
            self._send(lambda i=msg_id, h=hz: self.master.mav.command_long_send(
                ts, tc, mavutil.mavlink.MAV_CMD_SET_MESSAGE_INTERVAL, 0, i, 1e6 / h, 0, 0, 0, 0, 0))
        # Legacy fallback (some serial/telemetry setups)
        self._send(lambda: self.master.mav.request_data_stream_send(
            ts, tc, mavutil.mavlink.MAV_DATA_STREAM_ALL, 4, 1))

    def _reader(self):
        last_hb = 0.0
        while not self._stop.is_set():
            now = time.time()
            if now - last_hb >= 1.0:  # our GCS heartbeat (keeps FS_GCS happy)
                try:
                    self._send(lambda: self.master.mav.heartbeat_send(
                        mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0))
                except Exception:
                    pass
                last_hb = now
            try:
                msg = self.master.recv_match(blocking=True, timeout=0.2)
            except Exception:
                time.sleep(0.3)
                continue
            if msg is None:
                continue
            try:
                self._handle(msg)
            except Exception:
                pass

    def _handle(self, msg):
        mtype = msg.get_type()
        if mtype == "BAD_DATA":
            return
        if msg.get_srcSystem() != self.master.target_system:
            return
        self._last_rx = time.time()

        if mtype == "HEARTBEAT":
            if msg.get_srcComponent() != self.master.target_component:
                return
            self._t["armed"] = bool(msg.base_mode & mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED)
            self._t["mode"] = mavutil.mode_string_v10(msg)
        elif mtype == "GLOBAL_POSITION_INT":
            if msg.lat != 0 or msg.lon != 0:
                self._t["lat"] = msg.lat / 1e7
                self._t["lon"] = msg.lon / 1e7
            self._t["alt"] = msg.relative_alt / 1000.0
        elif mtype == "GPS_RAW_INT":
            self._t["fix"] = msg.fix_type
            self._t["sats"] = msg.satellites_visible
        elif mtype == "SYS_STATUS":
            if msg.voltage_battery != 65535:
                self._t["voltage"] = msg.voltage_battery / 1000.0
        elif mtype == "COMMAND_ACK":
            if msg.result != mavutil.mavlink.MAV_RESULT_IN_PROGRESS:
                self._acks[msg.command] = msg.result
        elif mtype == "STATUSTEXT":
            text = msg.text.decode("utf-8", "ignore") if isinstance(msg.text, (bytes, bytearray)) else msg.text
            text = text.rstrip("\x00").strip()
            self.statustexts.append(text)
            print(f"    [FCU] {text}", flush=True)

    # ---------------------------------------------------------------- state
    def telemetry(self) -> Dict[str, Any]:
        return dict(self._t)

    def link_age(self) -> float:
        return time.time() - self._last_rx

    # ---------------------------------------------------------------- commands
    def _command(self, cmd: int, params: List[float], timeout: float = 3.0, retries: int = 3) -> Optional[int]:
        """Send COMMAND_LONG and wait for COMMAND_ACK. Returns MAV_RESULT or None if no ack."""
        ts, tc = self.master.target_system, self.master.target_component
        p = list(params) + [0.0] * (7 - len(params))
        for _ in range(retries):
            self._acks.pop(cmd, None)
            self._send(lambda: self.master.mav.command_long_send(ts, tc, cmd, 0, *p))
            t_end = time.time() + timeout
            while time.time() < t_end:
                if cmd in self._acks:
                    return self._acks.pop(cmd)
                time.sleep(0.05)
        return None

    def wait_for_gps(self, timeout: float = 120.0, min_sats: int = 6) -> bool:
        print(f"[*] Waiting for 3D GPS fix (>= {min_sats} satellites) ...")
        t_end = time.time() + timeout
        last_print = 0.0
        while time.time() < t_end:
            t = self.telemetry()
            if t["fix"] >= 3 and t["sats"] >= min_sats and t["lat"] is not None:
                print(f"[+] GPS OK: fix={t['fix']}, sats={t['sats']}, position=({t['lat']:.6f}, {t['lon']:.6f})")
                time.sleep(1.0)
                return True
            if time.time() - last_print > 3.0:
                print(f"    ... GPS fix={t['fix']} sats={t['sats']} (waiting)", flush=True)
                last_print = time.time()
            time.sleep(0.5)
        return False

    def set_mode(self, mode: str, timeout: float = 4.0, attempts: int = 4) -> bool:
        mapping = mavutil.mode_mapping_byname(self.hb_type) or {}
        if mode not in mapping:
            print(f"[!] Mode {mode} is unknown for this vehicle type.")
            return False
        mode_id = mapping[mode]
        ts = self.master.target_system
        for i in range(attempts):
            if i % 2 == 0:
                self._send(lambda: self.master.mav.command_long_send(
                    ts, self.master.target_component, mavutil.mavlink.MAV_CMD_DO_SET_MODE, 0,
                    mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, mode_id, 0, 0, 0, 0, 0))
            else:
                self._send(lambda: self.master.mav.set_mode_send(
                    ts, mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, mode_id))
            t_end = time.time() + timeout
            while time.time() < t_end:
                if self._t["mode"] == mode:
                    return True
                time.sleep(0.1)
        return False

    def arm(self, force: bool = False, attempts: int = 5) -> bool:
        for i in range(1, attempts + 1):
            res = self._command(mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
                                [1, 21196 if force else 0], timeout=3.0, retries=1)
            t_end = time.time() + 6.0
            while time.time() < t_end:
                if self._t["armed"]:
                    return True
                time.sleep(0.1)
            name = "NO ACK" if res is None else MAV_RESULT_NAMES.get(res, str(res))
            print(f"[!] Arm attempt {i}/{attempts} failed (ack: {name}). Read the [FCU] 'PreArm:' lines above.")
            time.sleep(2.0)
        return False

    def takeoff(self, alt: float) -> bool:
        res = self._command(mavutil.mavlink.MAV_CMD_NAV_TAKEOFF, [0, 0, 0, 0, 0, 0, alt], timeout=3.0, retries=3)
        if res == mavutil.mavlink.MAV_RESULT_ACCEPTED:
            return True
        name = "NO ACK" if res is None else MAV_RESULT_NAMES.get(res, str(res))
        print(f"[!] Takeoff command rejected (ack: {name}).")
        return False

    def set_speed(self, speed: float):
        self._command(mavutil.mavlink.MAV_CMD_DO_CHANGE_SPEED, [1, speed, -1, 0], timeout=1.5, retries=1)

    def goto(self, lat: float, lon: float, alt: float):
        """Position-only GUIDED setpoint (alt relative to home). typemask 0x0DF8 = use x,y,z only."""
        ts, tc = self.master.target_system, self.master.target_component
        self._send(lambda: self.master.mav.set_position_target_global_int_send(
            0, ts, tc, mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT, 0x0DF8,
            int(lat * 1e7), int(lon * 1e7), alt, 0, 0, 0, 0, 0, 0, 0, 0))

    def land(self) -> bool:
        return self.set_mode("LAND")


# ==============================================================================
# 3B. SIMULATED VEHICLE (same interface, mimics ArduCopter rules)
# ==============================================================================
class SimVehicle:
    is_hardware = False

    def __init__(self, start_lat: float, start_lon: float):
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._speed = 3.0
        self._target = None
        self._takeoff_alt = None
        self._t: Dict[str, Any] = dict(lat=start_lat, lon=start_lon, alt=0.0, voltage=11.52,
                                       mode="STABILIZE", armed=False, fix=3, sats=12)
        self.statustexts = deque(maxlen=10)

    def connect(self) -> bool:
        print("[*] No --mavlink given: running in kinematic SIMULATION mode.")
        threading.Thread(target=self._run, daemon=True).start()
        return True

    def close(self):
        self._stop.set()

    def link_age(self) -> float:
        return 0.0

    def telemetry(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._t)

    def _run(self):
        dt = 0.1
        while not self._stop.is_set():
            with self._lock:
                t = self._t
                if t["armed"]:
                    t["voltage"] = max(10.1, t["voltage"] - 0.0002)
                    if t["mode"] == "GUIDED":
                        if self._takeoff_alt is not None:
                            t["alt"] = min(self._takeoff_alt, t["alt"] + 1.5 * dt)
                        if self._target:
                            tl, tn, ta = self._target
                            d = haversine_distance_m(t["lat"], t["lon"], tl, tn)
                            if d > 0.05:
                                r = min(d, self._speed * dt) / d
                                t["lat"] += (tl - t["lat"]) * r
                                t["lon"] += (tn - t["lon"]) * r
                            step = 1.0 * dt
                            t["alt"] += max(-step, min(step, ta - t["alt"]))
                    elif t["mode"] == "LAND":
                        t["alt"] = max(0.0, t["alt"] - 0.6 * dt)
                        if t["alt"] <= 0.05:
                            t["alt"], t["armed"] = 0.0, False
            time.sleep(dt)

    def wait_for_gps(self, timeout: float = 0.0, min_sats: int = 6) -> bool:
        return True

    def set_mode(self, mode: str, **_) -> bool:
        with self._lock:
            self._t["mode"] = mode
        return True

    def arm(self, force: bool = False, attempts: int = 1) -> bool:
        with self._lock:
            if self._t["mode"] != "GUIDED":
                return False
            self._t["armed"] = True
            return True

    def takeoff(self, alt: float) -> bool:
        with self._lock:
            if not (self._t["armed"] and self._t["mode"] == "GUIDED"):
                return False
            self._takeoff_alt = alt
            return True

    def set_speed(self, speed: float):
        self._speed = speed

    def goto(self, lat: float, lon: float, alt: float):
        with self._lock:
            self._target = (lat, lon, alt)

    def land(self) -> bool:
        with self._lock:
            self._t["mode"] = "LAND"
            self._target = None
            self._takeoff_alt = None
        return True


# ==============================================================================
# 4. AUTONOMOUS 4-WAYPOINT NAVIGATION CONTROLLER
# ==============================================================================
class DroneNavigationController:
    def __init__(self,
                 waypoints: List[Dict[str, Any]],
                 mavlink_conn: Optional[str] = None,
                 baudrate: int = 57600,
                 takeoff_alt: float = 5.0,
                 acceptance_radius_m: float = 2.0,
                 speed_m_s: float = 3.0,
                 force_arm: bool = False):
        self.waypoints = waypoints
        self.takeoff_alt = takeoff_alt
        self.acceptance_radius_m = acceptance_radius_m
        self.alt_tolerance_m = 1.5
        self.speed_m_s = speed_m_s
        self.force_arm = force_arm

        self.running = True
        self.emergency_stop = False
        self.status = "INITIALIZING"

        if mavlink_conn:
            self.vehicle = MavlinkVehicle(mavlink_conn, baudrate)
        else:
            self.vehicle = SimVehicle(waypoints[0]["lat"] + 0.0003, waypoints[0]["lon"] - 0.0003)

    # ------------------------------------------------------------------ helpers
    def print_banner(self):
        print("\n" + "=" * 90)
        print("          AUTONOMOUS 4-WAYPOINT DRONE NAVIGATION & LANDING MISSION CONTROLLER          ")
        print("=" * 90)
        print(f"[*] Total Waypoints      : {len(self.waypoints)}")
        print(f"[*] Takeoff Altitude     : {self.takeoff_alt:.1f} m")
        print(f"[*] Cruise Speed         : {self.speed_m_s:.1f} m/s")
        print(f"[*] Acceptance Radius    : {self.acceptance_radius_m:.1f} m")
        for idx, wp in enumerate(self.waypoints, start=1):
            print(f"    -> WP {idx} [{wp['name']}]: Lat={wp['lat']:.6f}, Lon={wp['lon']:.6f}, Alt={wp['alt']:.1f}m")
        print("=" * 90 + "\n")

    def _check_alive(self, expect_guided: bool = True):
        """Abort conditions checked in every flight loop."""
        if self.emergency_stop or not self.running:
            raise MissionAbort("emergency/stop requested")
        t = self.vehicle.telemetry()
        if self.vehicle.is_hardware:
            if expect_guided and t["mode"] != "GUIDED":
                raise MissionAbort(f"flight mode changed to {t['mode']} (pilot or failsafe took over) - "
                                   f"script is releasing control")
            if not t["armed"]:
                raise MissionAbort("vehicle is no longer armed")
            if self.vehicle.link_age() > 5.0:
                print(f"[!] WARNING: no MAVLink data for {self.vehicle.link_age():.0f}s", flush=True)

    # ------------------------------------------------------------------ phases
    def preflight_and_arm(self):
        self.status = "PREFLIGHT"
        print("[*] [STEP 0/3] PRE-FLIGHT: GPS -> GUIDED mode -> ARM")

        if not self.vehicle.wait_for_gps():
            raise MissionAbort("no 3D GPS fix (go outdoors / wait for satellites)")

        t = self.vehicle.telemetry()
        print(f"[*] Battery: {t['voltage']:.2f} V | Mode: {t['mode']} | Armed: {t['armed']}")

        if not t["armed"]:
            print("[*] Switching to GUIDED mode ...")
            if not self.vehicle.set_mode("GUIDED"):
                raise MissionAbort("could not switch to GUIDED (check the [FCU] messages above)")
            print("[+] Mode is GUIDED.")

            if self.force_arm:
                print("[!] --force-arm is ON: ARMING CHECKS ARE BYPASSED. Only use for bench diagnosis.")
            print("[*] Arming motors ...")
            if not self.vehicle.arm(force=self.force_arm):
                raise MissionAbort(
                    "ARMING FAILED. Typical causes (see the 'PreArm:' text printed above):\n"
                    "      - Hardware safety switch not pressed (Cube Orange: hold the button until solid red LED)\n"
                    "      - Compass / accelerometer not calibrated, or gyros/EKF still initialising\n"
                    "      - RC transmitter off or throttle failsafe (set to a valid RC, or configure FS_THR_ENABLE)\n"
                    "      - Battery voltage below BATT_ARM_VOLT, or GPS HDOP too high\n"
                    "      - Flight mode not allowed to arm (must be GUIDED / STABILIZE / LOITER ...)")
        else:
            print("[*] Vehicle already armed.")
            if self.vehicle.telemetry()["mode"] != "GUIDED" and not self.vehicle.set_mode("GUIDED"):
                raise MissionAbort("could not switch to GUIDED")
        print("[+] MOTORS ARMED.\n")

    def takeoff_phase(self):
        self.status = "TAKEOFF"
        print(f"[*] [STEP 1/3] TAKING OFF TO {self.takeoff_alt:.1f} m ...")
        # Must be sent right after arming, otherwise ArduCopter disarms after ~10 s.
        if not self.vehicle.takeoff(self.takeoff_alt):
            raise MissionAbort("takeoff command rejected - vehicle must be ARMED and in GUIDED")

        t_start = time.time()
        last_alt, last_progress = -1.0, time.time()
        while True:
            self._check_alive()
            t = self.vehicle.telemetry()
            print(f"    -> Climbing: Alt={t['alt']:5.2f}m / {self.takeoff_alt:.1f}m | "
                  f"Bat={t['voltage']:5.2f}V | Mode={t['mode']}", flush=True)

            if t["alt"] >= self.takeoff_alt - 0.5:
                print(f"[+] Takeoff complete at {t['alt']:.2f} m.\n")
                time.sleep(1.5)
                return
            if t["alt"] > last_alt + 0.1:
                last_alt, last_progress = t["alt"], time.time()
            if time.time() - last_progress > 15.0 and t["alt"] < 0.5:
                raise MissionAbort("motors armed but vehicle is not climbing (check props/motors/RC failsafe)")
            if time.time() - t_start > 90.0:
                raise MissionAbort("takeoff timeout")
            time.sleep(0.5)

    def navigate_to_waypoint(self, wp_idx: int, wp: Dict[str, Any]):
        name = wp["name"]
        t_lat, t_lon, t_alt = wp["lat"], wp["lon"], wp.get("alt", self.takeoff_alt)
        self.status = f"FLYING_TO_WP_{wp_idx + 1}"
        print("-" * 90)
        print(f"[*] [STEP 2/3] EN ROUTE TO {name.upper()} (Lat={t_lat:.6f}, Lon={t_lon:.6f}, Alt={t_alt:.1f}m)")
        print("-" * 90)

        t = self.vehicle.telemetry()
        start_dist = max(1.0, haversine_distance_m(t["lat"], t["lon"], t_lat, t_lon))
        timeout = 60.0 + 3.0 * start_dist / max(0.5, self.speed_m_s)
        t_start = time.time()
        last_send = 0.0

        while True:
            self._check_alive()
            if time.time() - last_send >= 1.0:  # keep re-sending the target
                self.vehicle.goto(t_lat, t_lon, t_alt)
                last_send = time.time()

            t = self.vehicle.telemetry()
            dist = haversine_distance_m(t["lat"], t["lon"], t_lat, t_lon)
            alt_err = abs(t["alt"] - t_alt)
            progress = max(0.0, min(100.0, (1.0 - dist / start_dist) * 100.0))
            print(f"    -> [{name}] Dist: {dist:6.2f}m | Progress: {progress:5.1f}% | "
                  f"GPS: ({t['lat']:.6f}, {t['lon']:.6f}) | Alt: {t['alt']:4.1f}m | Bat: {t['voltage']:4.2f}V",
                  flush=True)

            if dist <= self.acceptance_radius_m and alt_err <= self.alt_tolerance_m:
                print(f"[+] REACHED {name.upper()} (distance {dist:.2f} m). Holding 2 s ...\n")
                time.sleep(2.0)
                return
            if time.time() - t_start > timeout:
                raise MissionAbort(f"timeout while flying to {name}")
            time.sleep(0.5)

    def execute_final_landing(self):
        self.status = "LANDING"
        t = self.vehicle.telemetry()
        print("=" * 90)
        print(f"[*] [STEP 3/3] LANDING AT FINAL WAYPOINT ({t['lat']:.6f}, {t['lon']:.6f}) ...")
        print("=" * 90)
        if not self.vehicle.land():
            print("[!] LAND mode change not confirmed - retrying ...")
            if not self.vehicle.land():
                raise MissionAbort("could not switch to LAND")
        if not self._wait_for_disarm(timeout=180.0, label="Descending"):
            raise MissionAbort("landing not confirmed within timeout")

        t = self.vehicle.telemetry()
        self.status = "MISSION_COMPLETED"
        print("\n" + "=" * 90)
        print("  [SUCCESS] TOUCHDOWN CONFIRMED - MOTORS DISARMED.")
        print(f"  Final position : Lat={t['lat']:.6f}, Lon={t['lon']:.6f}")
        print(f"  Battery        : {t['voltage']:.2f} V")
        print("  Mission        : ALL 4 WAYPOINTS COMPLETED & LANDED SAFELY")
        print("=" * 90 + "\n")

    def _wait_for_disarm(self, timeout: float, label: str = "Landing") -> bool:
        t_end = time.time() + timeout
        while time.time() < t_end:
            t = self.vehicle.telemetry()
            print(f"    -> {label}: Alt={t['alt']:5.2f}m | Mode={t['mode']} | Armed={t['armed']}", flush=True)
            if not t["armed"]:
                return True
            time.sleep(1.0)
        return False

    def trigger_emergency_land(self, reason: str = "Operator Triggered"):
        if self.emergency_stop:
            return
        self.emergency_stop = True
        self.status = "EMERGENCY_LAND"
        print(f"\n[!] EMERGENCY LAND TRIGGERED ({reason})! Switching to LAND ...")
        try:
            self.vehicle.land()
        except Exception as e:
            print(f"[!] Could not send LAND: {e}")

    # ------------------------------------------------------------------ main flow
    def run_mission(self):
        self.print_banner()
        if not self.vehicle.connect():
            print("[!] Mission aborted: no connection to the flight controller.")
            return

        try:
            self.preflight_and_arm()
            self.takeoff_phase()
            self.vehicle.set_speed(self.speed_m_s)
            for idx, wp in enumerate(self.waypoints):
                self.navigate_to_waypoint(idx, wp)
            self.execute_final_landing()

        except MissionAbort as e:
            print(f"\n[!] MISSION ABORTED: {e}")
            t = self.vehicle.telemetry()
            if self.emergency_stop:
                print("[*] Waiting for the vehicle to land and disarm ...")
                self._wait_for_disarm(timeout=180.0, label="Emergency landing")
            elif self.vehicle.is_hardware and t["armed"] and t["mode"] == "GUIDED":
                # We were in control and something failed: put the vehicle down safely.
                print("[!] Vehicle still armed in GUIDED -> commanding LAND for safety.")
                self.vehicle.land()
                self._wait_for_disarm(timeout=180.0, label="Safety landing")
            elif t["armed"]:
                print("[*] Vehicle is armed but not in GUIDED - leaving control to the pilot.")

    def stop(self):
        self.running = False
        try:
            self.vehicle.close()
        except Exception:
            pass


# ==============================================================================
# 5. KEYBOARD LISTENER THREAD (PRESS 'b' FOR EMERGENCY LAND)
# ==============================================================================
def start_keyboard_listener(controller: DroneNavigationController):
    def listener():
        print("[*] Safety: type 'b' + Enter to LAND immediately.\n")
        while controller.running:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                cmd = line.strip().lower()
                if cmd in ("b", "land", "emergency"):
                    controller.trigger_emergency_land(reason="Operator 'b' hotkey")
                elif cmd in ("q", "quit", "exit"):
                    controller.trigger_emergency_land(reason="Operator quit")
                    break
            except Exception:
                break

    threading.Thread(target=listener, daemon=True).start()


# ==============================================================================
# 6. CLI ARGUMENT PARSER & INTERACTIVE COORDINATE INPUT
# ==============================================================================
def parse_coordinate_str(s: str, default_alt: float = 5.0) -> Dict[str, float]:
    """Parses 'lat,lon' or 'lat,lon,alt'."""
    parts = [float(p.strip()) for p in s.split(",") if p.strip()]
    return {"lat": parts[0], "lon": parts[1], "alt": parts[2] if len(parts) >= 3 else default_alt}


def prompt_user_for_4_waypoints() -> List[Dict[str, Any]]:
    print("\n" + "=" * 70)
    print("   ENTER 4 GPS WAYPOINTS  (Format: Latitude, Longitude, Altitude_Meters)")
    print("=" * 70)
    wps = []
    for i in range(1, 5):
        label = f"Waypoint {i}" if i < 4 else "Waypoint 4 (Final Landing Site)"
        d = DEFAULT_WAYPOINTS[i - 1]
        inp = input(f"[*] Enter {label} [Default: {d['lat']}, {d['lon']}, {d['alt']}]: ").strip()
        if not inp:
            wps.append({"name": label, "lat": d["lat"], "lon": d["lon"], "alt": d["alt"]})
        else:
            c = parse_coordinate_str(inp, default_alt=5.0)
            wps.append({"name": label, **c})
    return wps


def main():
    parser = argparse.ArgumentParser(description="Autonomous 4-Waypoint Drone Navigation & Landing (ArduCopter)")
    parser.add_argument("--mavlink", type=str, default=None,
                        help="Connection string, e.g. COM3, /dev/ttyACM0, /dev/ttyAMA0, udp:127.0.0.1:14550. "
                             "Omit for simulation.")
    parser.add_argument("--mavlink-baud", type=int, default=57600, help="Serial baud rate (default 57600)")
    parser.add_argument("--alt", type=float, default=5.0, help="Takeoff altitude in meters (default 5.0)")
    parser.add_argument("--radius", type=float, default=2.0, help="Waypoint acceptance radius in meters (default 2.0)")
    parser.add_argument("--speed", type=float, default=3.0, help="Horizontal speed in m/s (default 3.0)")
    parser.add_argument("--force-arm", action="store_true",
                        help="DANGEROUS: bypass ArduPilot pre-arm checks (bench diagnosis only, props off)")
    parser.add_argument("--interactive", action="store_true", help="Prompt for all 4 waypoints")
    parser.add_argument("--wp1", type=str, default=None, help="'lat,lon' or 'lat,lon,alt'")
    parser.add_argument("--wp2", type=str, default=None, help="'lat,lon' or 'lat,lon,alt'")
    parser.add_argument("--wp3", type=str, default=None, help="'lat,lon' or 'lat,lon,alt'")
    parser.add_argument("--wp4", type=str, default=None, help="Final landing waypoint: 'lat,lon' or 'lat,lon,alt'")
    args = parser.parse_args()

    if args.interactive:
        waypoints = prompt_user_for_4_waypoints()
    else:
        waypoints = []
        for idx, inp in enumerate([args.wp1, args.wp2, args.wp3, args.wp4]):
            d = DEFAULT_WAYPOINTS[idx]
            name = f"Waypoint {idx + 1}" if idx < 3 else "Waypoint 4 (Final Landing Site)"
            if inp:
                p = parse_coordinate_str(inp, default_alt=args.alt)
                waypoints.append({"name": name, **p})
            else:
                waypoints.append({"name": name, "lat": d["lat"], "lon": d["lon"], "alt": d["alt"]})

    controller = DroneNavigationController(
        waypoints=waypoints,
        mavlink_conn=args.mavlink,
        baudrate=args.mavlink_baud,
        takeoff_alt=args.alt,
        acceptance_radius_m=args.radius,
        speed_m_s=args.speed,
        force_arm=args.force_arm,
    )
    start_keyboard_listener(controller)

    try:
        controller.run_mission()
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C detected -> LAND.")
        controller.trigger_emergency_land(reason="Ctrl+C")
        try:
            controller._wait_for_disarm(timeout=180.0, label="Emergency landing")
        except KeyboardInterrupt:
            pass
    finally:
        controller.stop()


if __name__ == "__main__":
    main()
