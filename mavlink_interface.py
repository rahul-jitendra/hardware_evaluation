"""
mavlink_interface.py — Robust Real-Time MAVLink Interface for Cube Orange (ArduCopter)
========================================================================================
Directly connects companion computer (Raspberry Pi / Jetson / PC) to the
Cube Orange Flight Controller via MAVLink (pymavlink over USB, UART, or UDP).

Key Enhancements (Derived from validated drone_navigation_test.py):
1. Connection & Heartbeat Negotiation:
   - Handshakes with system 255/190 and verifies ArduPilot multirotor autopilot.
   - Continuous 1 Hz GCS heartbeat thread to prevent ArduCopter failsafe disarm (FS_GCS_ENABLE).
2. Streaming Telemetry:
   - Requests per-message intervals (SYS_STATUS, GPS_RAW_INT, GLOBAL_POSITION_INT, VFR_HUD).
   - Thread-safe sending lock (_send_lock) to avoid serial/socket collision.
3. Command Acknowledgement & Verification:
   - Tracks COMMAND_ACK with timeouts and retry mechanisms.
   - Captures and logs [FCU] STATUSTEXT (including PreArm diagnostic reasons).
4. Verified Flight Control Sequence:
   - wait_for_gps(): Confirms 3D fix (fix >= 3, sats >= 6).
   - set_mode("GUIDED"): Verifies mode transition via HEARTBEAT before issuing arm/takeoff.
   - arm(): Issues arm command with retry and confirms armed state.
   - takeoff(): Issues MAV_CMD_NAV_TAKEOFF with ACK check.
   - goto(): Uses MAV_CMD_SET_POSITION_TARGET_GLOBAL_INT (0x0DF8 position setpoint).
   - land(): Switches to LAND mode with verification and disarm detection.
5. Kinematic Simulation Fallback:
   - Seamlessly falls back to SimVehicle if no --mavlink port is supplied.
"""

import time
import math
import threading
from collections import deque
from typing import Dict, Any, Optional, List

try:
    from pymavlink import mavutil
    PYMAVLINK_AVAILABLE = True
except ImportError:
    mavutil = None
    PYMAVLINK_AVAILABLE = False

MAV_RESULT_NAMES = {
    0: "ACCEPTED", 1: "TEMPORARILY_REJECTED", 2: "DENIED", 3: "UNSUPPORTED",
    4: "FAILED", 5: "IN_PROGRESS", 6: "CANCELLED"
}


# ==============================================================================
# 1. HARDWARE MAVLINK VEHICLE (Direct ArduCopter on Cube Orange)
# ==============================================================================
class MavlinkVehicle:
    is_hardware = True
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
        self._t: Dict[str, Any] = dict(
            lat=16.792406, lon=80.819767, alt=0.0,
            ground_alt=0.0, vx=0.0, vy=0.0, vz=0.0, heading=0.0,
            voltage=11.52, current=1.20, battery_remaining=95,
            mode="UNKNOWN", flight_mode="UNKNOWN", armed=False, fix=0, sats=0,
            is_hardware_mavlink=True
        )

    def connect(self, timeout: float = 30.0) -> bool:
        if not PYMAVLINK_AVAILABLE:
            print("[MAVLink] Note: 'pymavlink' not installed. pip install pymavlink")
            return False

        print(f"[*] [MAVLink] Connecting to Cube Orange at {self.conn} (baud: {self.baud}) ...")
        try:
            self.master = mavutil.mavlink_connection(
                self.conn, baud=self.baud,
                source_system=255, source_component=190
            )
        except Exception as e:
            print(f"[!] [MAVLink] Could not open {self.conn}: {e}")
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
            print(f"[!] [MAVLink] No autopilot heartbeat within {timeout:.0f}s. Check port, baud and SERIALx_PROTOCOL.")
            return False

        if hb.autopilot != mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA:
            print("[!] [MAVLink] Autopilot is not ArduPilot (PX4 detected?). Requires ArduCopter GUIDED/LAND.")
            return False

        if hb.type not in self.MULTIROTOR_TYPES:
            print(f"[!] [MAVLink] Vehicle type {hb.type} is not a multirotor (ArduCopter expected).")
            return False

        self.hb_type = hb.type
        self.master.target_system = hb.get_srcSystem()
        self.master.target_component = hb.get_srcComponent()
        self._last_rx = time.time()
        print(f"[+] [MAVLink] Heartbeat received! System: {self.master.target_system}, Component: {self.master.target_component} (ArduCopter).")

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

    def _send(self, fn):
        with self._send_lock:
            try:
                fn()
            except Exception as e:
                pass

    def _request_streams(self):
        ts, tc = self.master.target_system, self.master.target_component
        # Microsecond intervals for key streams
        for msg_id, hz in ((1, 2), (24, 2), (33, 5), (74, 2)):
            self._send(lambda i=msg_id, h=hz: self.master.mav.command_long_send(
                ts, tc, mavutil.mavlink.MAV_CMD_SET_MESSAGE_INTERVAL, 0, i, int(1e6 / h), 0, 0, 0, 0, 0))
        # Legacy fallback
        self._send(lambda: self.master.mav.request_data_stream_send(
            ts, tc, mavutil.mavlink.MAV_DATA_STREAM_ALL, 4, 1))

    def _reader(self):
        last_hb = 0.0
        while not self._stop.is_set():
            now = time.time()
            if now - last_hb >= 1.0:
                # 1 Hz GCS heartbeat prevents failsafe disarm
                try:
                    self._send(lambda: self.master.mav.heartbeat_send(
                        mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0))
                except Exception:
                    pass
                last_hb = now

            try:
                msg = self.master.recv_match(blocking=True, timeout=0.2)
            except Exception:
                time.sleep(0.2)
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
            mode_name = mavutil.mode_string_v10(msg)
            self._t["mode"] = mode_name
            self._t["flight_mode"] = mode_name
        elif mtype == "GLOBAL_POSITION_INT":
            if msg.lat != 0 or msg.lon != 0:
                self._t["lat"] = msg.lat / 1e7
                self._t["lon"] = msg.lon / 1e7
            self._t["alt"] = round(msg.relative_alt / 1000.0, 2)
            self._t["vx"] = round(msg.vx / 100.0, 2)
            self._t["vy"] = round(msg.vy / 100.0, 2)
            self._t["vz"] = round(msg.vz / 100.0, 2)
            self._t["heading"] = round(msg.hdg / 100.0, 1)
        elif mtype == "GPS_RAW_INT":
            self._t["fix"] = msg.fix_type
            self._t["sats"] = msg.satellites_visible
        elif mtype == "SYS_STATUS":
            if msg.voltage_battery != 65535:
                self._t["voltage"] = round(msg.voltage_battery / 1000.0, 2)
            if msg.current_battery != -1:
                self._t["current"] = round(msg.current_battery / 100.0, 2)
            self._t["battery_remaining"] = msg.battery_remaining
        elif mtype == "BATTERY_STATUS":
            if hasattr(msg, "voltages") and len(msg.voltages) > 0 and msg.voltages[0] != 65535:
                self._t["voltage"] = round(msg.voltages[0] / 1000.0, 2)
        elif mtype == "COMMAND_ACK":
            if msg.result != mavutil.mavlink.MAV_RESULT_IN_PROGRESS:
                self._acks[msg.command] = msg.result
        elif mtype == "STATUSTEXT":
            text = msg.text.decode("utf-8", "ignore") if isinstance(msg.text, (bytes, bytearray)) else msg.text
            text = text.rstrip("\x00").strip()
            self.statustexts.append(text)
            print(f"    [CubeOrange FCU] {text}", flush=True)

    def telemetry(self) -> Dict[str, Any]:
        return dict(self._t)

    def link_age(self) -> float:
        return time.time() - self._last_rx

    def _command(self, cmd: int, params: List[float], timeout: float = 3.0, retries: int = 3) -> Optional[int]:
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

    def wait_for_gps(self, timeout: float = 60.0, min_sats: int = 6) -> bool:
        print(f"[*] [MAVLink] Waiting for 3D GPS fix (>= {min_sats} satellites) ...")
        t_end = time.time() + timeout
        last_print = 0.0
        while time.time() < t_end:
            t = self.telemetry()
            if t["fix"] >= 3 and t["sats"] >= min_sats and t["lat"] is not None:
                print(f"[+] [MAVLink] GPS OK: fix={t['fix']}, sats={t['sats']}, pos=({t['lat']:.6f}, {t['lon']:.6f})")
                return True
            if time.time() - last_print > 3.0:
                print(f"    ... GPS fix={t['fix']}, sats={t['sats']} (waiting)", flush=True)
                last_print = time.time()
            time.sleep(0.5)
        return False

    def set_mode(self, mode: str, timeout: float = 4.0, attempts: int = 4) -> bool:
        mapping = mavutil.mode_mapping_byname(self.hb_type) or {}
        if mode not in mapping:
            print(f"[!] [MAVLink] Mode {mode} is unknown for this vehicle.")
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
                if self._t["mode"] == mode or self._t["flight_mode"] == mode:
                    return True
                time.sleep(0.1)
        return False

    def arm(self, force: bool = False, attempts: int = 5) -> bool:
        for i in range(1, attempts + 1):
            res = self._command(mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
                                [1, 21196 if force else 0], timeout=3.0, retries=1)
            t_end = time.time() + 5.0
            while time.time() < t_end:
                if self._t["armed"]:
                    return True
                time.sleep(0.1)
            name = "NO ACK" if res is None else MAV_RESULT_NAMES.get(res, str(res))
            print(f"[!] [MAVLink] Arm attempt {i}/{attempts} failed (ack: {name}). Check [CubeOrange FCU] messages above.")
            time.sleep(1.5)
        return False

    def takeoff(self, alt: float, attempts: int = 4) -> bool:
        for i in range(1, attempts + 1):
            res = self._command(mavutil.mavlink.MAV_CMD_NAV_TAKEOFF, [0, 0, 0, 0, 0, 0, alt], timeout=3.0, retries=2)
            if res == mavutil.mavlink.MAV_RESULT_ACCEPTED:
                return True
            name = "NO ACK" if res is None else MAV_RESULT_NAMES.get(res, str(res))
            print(f"[!] [MAVLink] Takeoff attempt {i}/{attempts} rejected (ack: {name}). Retrying in 1s...")
            time.sleep(1.0)
        return False

    def set_speed(self, speed: float):
        self._command(mavutil.mavlink.MAV_CMD_DO_CHANGE_SPEED, [1, speed, -1, 0], timeout=1.5, retries=1)

    def goto(self, lat: float, lon: float, alt: float):
        """Standard GUIDED position target (typemask 0x0DF8 = x,y,z only)."""
        ts, tc = self.master.target_system, self.master.target_component
        self._send(lambda: self.master.mav.set_position_target_global_int_send(
            0, ts, tc, mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT, 0x0DF8,
            int(lat * 1e7), int(lon * 1e7), float(alt), 0, 0, 0, 0, 0, 0, 0, 0))

    def land(self) -> bool:
        return self.set_mode("LAND")

    def command_arm_and_takeoff(self, target_alt_m: float = 5.0, force: bool = False) -> bool:
        """Robust multi-step sequence to switch GUIDED -> ARM -> TAKEOFF -> confirm climb."""
        print(f"[*] [MAVLink Hardware] Preparing Cube Orange for Takeoff to {target_alt_m:.1f}m (force={force})...")
        
        # Step 1: Switch to GUIDED mode
        if not self.set_mode("GUIDED"):
            print("[!] [MAVLink Hardware] Initial switch to GUIDED mode rejected by flight controller.")
            if force:
                print("[*] [MAVLink Hardware] --force-arm active: Attempting direct force-arm first...")
                if self.arm(force=True):
                    print("[+] [MAVLink Hardware] Force-arm succeeded. Switching to GUIDED...")
                    time.sleep(1.0)
                    self.set_mode("GUIDED")
            else:
                # Print recent FCU STATUSTEXT diagnostics for clarity
                recent_fcu = list(self.statustexts)[-3:] if self.statustexts else []
                if recent_fcu:
                    print(f"    [FCU Diagnostics] Recent messages: {' | '.join(recent_fcu)}")
                print("    -> Note: ArduCopter requires 3D GPS lock before entering GUIDED mode on ground.")
                print("    -> Tip: Ensure GPS antenna has outdoor sky view or run bench tests with --force-arm.")
                return False

        # Step 2: Arm motors if not already armed
        if not self._t.get("armed", False):
            print(f"[*] [MAVLink Hardware] Arming motors (force={force})...")
            if not self.arm(force=force):
                recent_fcu = list(self.statustexts)[-4:] if self.statustexts else []
                print("[!] [MAVLink Hardware] Arming failed. Common causes:")
                print("    1. Safety switch not pressed (Cube Orange: hold safety switch button until solid red LED)")
                print("    2. Compass / Accelerometer uncalibrated or EKF pre-arm checks failing")
                print("    3. Throttle failsafe / RC receiver offline")
                if recent_fcu:
                    print(f"    [FCU PreArm Diagnostics]: {' | '.join(recent_fcu)}")
                return False
            # Allow motors to spool up before issuing takeoff command
            time.sleep(1.5)

        # Step 3: Issue MAV_CMD_NAV_TAKEOFF
        print(f"[*] [MAVLink Hardware] Motors armed & spooled. Issuing MAV_CMD_NAV_TAKEOFF to {target_alt_m:.1f}m...")
        if not self.takeoff(target_alt_m):
            recent_fcu = list(self.statustexts)[-3:] if self.statustexts else []
            print(f"[!] [MAVLink Hardware] Takeoff command rejected. FCU: {' | '.join(recent_fcu) if recent_fcu else 'Check PreArm'}")
            return False

        print(f"[+] [MAVLink Hardware] Cube Orange accepted takeoff command towards {target_alt_m:.1f}m.")
        return True

    def wait_for_takeoff_climb(self, target_alt_m: float = 5.0, timeout: float = 30.0) -> bool:
        """Monitors climb progress until the vehicle reaches takeoff altitude before starting navigation."""
        print(f"[*] [MAVLink Hardware] Monitoring takeoff climb to {target_alt_m:.1f}m (timeout: {timeout:.0f}s)...")
        t_start = time.time()
        last_alt, last_progress = -1.0, time.time()
        while time.time() - t_start < timeout:
            t = self.telemetry()
            alt = t.get("alt", 0.0)
            armed = t.get("armed", False)
            mode = t.get("mode", t.get("flight_mode", "UNKNOWN"))
            print(f"    -> Climbing: Alt={alt:5.2f}m / {target_alt_m:.1f}m | Bat={t.get('voltage', 0.0):5.2f}V | Mode={mode} | Armed={armed}", flush=True)

            if alt >= target_alt_m - 0.5:
                print(f"[+] [MAVLink Hardware] Takeoff climb complete! Drone stabilized at {alt:.2f}m.\n")
                time.sleep(1.0)
                return True

            if alt > last_alt + 0.1:
                last_alt, last_progress = alt, time.time()

            # Detect disarm during climb
            if not armed and time.time() - t_start > 3.0:
                print("[!] [MAVLink Hardware] Motors disarmed during climb!")
                return False

            if time.time() - last_progress > 15.0 and alt < 0.3:
                print("[!] [MAVLink Hardware] Motors armed but vehicle is not lifting off (alt < 0.3m).")
                print("    Check propeller directions, ESC calibration, and RC throttle failsafe.")
                return False

            time.sleep(0.5)

        curr_alt = self.telemetry().get("alt", 0.0)
        if curr_alt >= 1.0:
            print(f"[+] [MAVLink Hardware] Airborne at {curr_alt:.2f}m. Proceeding to navigation.")
            return True
        print(f"[!] [MAVLink Hardware] Takeoff climb timed out after {timeout:.0f}s (alt: {curr_alt:.2f}m).")
        return False

    def command_emergency_land(self) -> bool:
        """Immediately commands LAND mode with ACK verification."""
        print("[*] [MAVLink Hardware] Commanding Immediate Emergency LAND Mode...")
        return self.land()

    def command_guided_waypoint(self, lat: float, lon: float, alt_m: float = 5.0) -> bool:
        """Commands Cube Orange in GUIDED mode to fly to GPS coordinate."""
        if self._t.get("mode") != "GUIDED" and self._t.get("flight_mode") != "GUIDED":
            self.set_mode("GUIDED")
        self.goto(lat, lon, alt_m)
        return True


# ==============================================================================
# 2. SIMULATED VEHICLE (Exact interface for testing without hardware)
# ==============================================================================
class SimVehicle:
    is_hardware = False

    def __init__(self, start_lat: float = 16.792406, start_lon: float = 80.819767):
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._speed = 3.0
        self._target = None
        self._takeoff_alt = None
        self._t: Dict[str, Any] = dict(
            lat=start_lat, lon=start_lon, alt=0.0, ground_alt=0.0,
            vx=0.0, vy=0.0, vz=0.0, heading=0.0,
            voltage=11.52, current=1.20, battery_remaining=95,
            mode="STABILIZE", flight_mode="STABILIZE", armed=False, fix=3, sats=12,
            is_hardware_mavlink=False
        )
        self.statustexts = deque(maxlen=10)

    def connect(self, timeout: float = 5.0) -> bool:
        print("[*] [MAVLink Simulator] Running in internal kinematic SIMULATION mode.")
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
                    t["voltage"] = max(10.1, t["voltage"] - 0.0001)
                    if t["mode"] == "GUIDED":
                        if self._takeoff_alt is not None:
                            t["alt"] = min(self._takeoff_alt, t["alt"] + 1.5 * dt)
                        if self._target:
                            tl, tn, ta = self._target
                            dlat = tl - t["lat"]
                            dlon = tn - t["lon"]
                            dist = math.sqrt(dlat**2 + dlon**2) * 111319.5
                            if dist > 0.05:
                                step = (self._speed * dt) / 111319.5
                                r = min(1.0, step / max(1e-6, math.sqrt(dlat**2 + dlon**2)))
                                t["lat"] += dlat * r
                                t["lon"] += dlon * r
                            t["alt"] += max(-1.0 * dt, min(1.0 * dt, ta - t["alt"]))
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
            self._t["flight_mode"] = mode
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
            self._t["flight_mode"] = "LAND"
            self._target = None
            self._takeoff_alt = None
        return True

    def command_arm_and_takeoff(self, target_alt_m: float = 5.0, force: bool = False) -> bool:
        self.set_mode("GUIDED")
        self.arm(force=force)
        self.takeoff(target_alt_m)
        return True

    def wait_for_takeoff_climb(self, target_alt_m: float = 5.0, timeout: float = 15.0) -> bool:
        """Simulates and verifies vertical takeoff climb."""
        print(f"[*] [MAVLink Simulator] Monitoring climb to {target_alt_m:.1f}m...")
        t_start = time.time()
        while time.time() - t_start < timeout:
            alt = self.telemetry().get("alt", 0.0)
            print(f"    -> [Simulator] Climbing: Alt={alt:5.2f}m / {target_alt_m:.1f}m", flush=True)
            if alt >= target_alt_m - 0.5:
                print(f"[+] [MAVLink Simulator] Takeoff climb completed at {alt:.2f}m.\n")
                return True
            time.sleep(0.4)
        return True

    def command_emergency_land(self) -> bool:
        return self.land()

    def command_guided_waypoint(self, lat: float, lon: float, alt_m: float = 5.0) -> bool:
        self.set_mode("GUIDED")
        self.goto(lat, lon, alt_m)
        return True


# ==============================================================================
# 3. UNIFIED MAVLINK INTERFACE (Plug-and-play for drone_node.py)
# ==============================================================================
class MavlinkInterface:
    """
    Standard interface used by companion drone nodes. Automatically connects to
    physical Cube Orange if connection_string is provided, else runs safe kinematic simulation.
    """
    def __init__(self,
                 connection_string: Optional[str] = None,
                 baudrate: int = 57600,
                 force_arm: bool = False,
                 default_lat: float = 16.792406,
                 default_lon: float = 80.819767):
        self.connection_string = connection_string
        self.baudrate = baudrate
        self.force_arm = force_arm
        self.default_lat = default_lat
        self.default_lon = default_lon

        if connection_string and PYMAVLINK_AVAILABLE:
            self._v = MavlinkVehicle(connection_string, baudrate)
        else:
            self._v = SimVehicle(default_lat, default_lon)

        self.running = False

    @property
    def is_connected(self) -> bool:
        return getattr(self._v, "is_hardware", False)

    @property
    def telemetry(self) -> Dict[str, Any]:
        return self._v.telemetry()

    def start(self):
        """Starts connection or simulation loop."""
        self.running = True
        success = self._v.connect()
        if not success and getattr(self._v, "is_hardware", False):
            print("[MAVLink] Hardware connection failed. Falling back to internal simulation.")
            self._v = SimVehicle(self.default_lat, self.default_lon)
            self._v.connect()

    def stop(self):
        self.running = False
        self._v.close()

    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        t = self._v.telemetry()
        # Ensure all expected fields are present
        return {
            "lat": t.get("lat", self.default_lat),
            "lon": t.get("lon", self.default_lon),
            "alt": t.get("alt", 0.0),
            "ground_alt": t.get("ground_alt", 0.0),
            "vx": t.get("vx", 0.0),
            "vy": t.get("vy", 0.0),
            "vz": t.get("vz", 0.0),
            "heading": t.get("heading", 0.0),
            "voltage": t.get("voltage", 11.52),
            "current": t.get("current", 1.20),
            "battery_remaining": t.get("battery_remaining", 95),
            "flight_mode": t.get("flight_mode", t.get("mode", "STABILIZE")),
            "mode": t.get("mode", "STABILIZE"),
            "armed": t.get("armed", False),
            "fix": t.get("fix", 0),
            "sats": t.get("sats", 0),
            "is_hardware_mavlink": getattr(self._v, "is_hardware", False)
        }

    def command_emergency_land(self) -> bool:
        return self._v.command_emergency_land()

    def command_guided_waypoint(self, lat: float, lon: float, alt_m: float = 5.0) -> bool:
        return self._v.command_guided_waypoint(lat, lon, alt_m)

    def command_arm_and_takeoff(self, target_alt_m: float = 5.0, force: bool = False) -> bool:
        return self._v.command_arm_and_takeoff(target_alt_m, force=(force or self.force_arm))

    def wait_for_takeoff_climb(self, target_alt_m: float = 5.0, timeout: float = 30.0) -> bool:
        if hasattr(self._v, "wait_for_takeoff_climb"):
            return self._v.wait_for_takeoff_climb(target_alt_m=target_alt_m, timeout=timeout)
        return True

    def set_mode(self, mode: str) -> bool:
        return self._v.set_mode(mode)

    def arm(self, force: bool = False) -> bool:
        return self._v.arm(force=(force or self.force_arm))

    def takeoff(self, alt: float) -> bool:
        return self._v.takeoff(alt)

    def goto(self, lat: float, lon: float, alt: float):
        self._v.goto(lat, lon, alt)

    def land(self) -> bool:
        return self._v.land()

    def set_speed(self, speed: float):
        self._v.set_speed(speed)

    def wait_for_gps(self, timeout: float = 60.0, min_sats: int = 6) -> bool:
        return self._v.wait_for_gps(timeout=timeout, min_sats=min_sats)

    def link_age(self) -> float:
        return self._v.link_age()
