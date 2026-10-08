"""
gui_dashboard.py — Real-Time 4-Drone Multi-Terminal Dashboard & Cyber Attack Console
=====================================================================================
Features:
1. 4 Dedicated Live Terminal Consoles (Drone 1, Drone 2, Drone 3, Backup Drone):
   - Real-time scrolling output of PQC handshakes, telemetry streams, decrypted peer RX,
     local AI IDS evaluations (XGBoost + Mondrian Conformal Prediction), and failover alerts.
   - Interactive CLI command input per drone (commands: help, status, peers, trust, rekey, handshake, isolate, clear).
2. Multi-Drone Tactical Attack & Fault Injection Bar (Universal target selection):
   - ⚡ GPS Spoofing Attack
   - 🔄 Cryptographic Replay Attack
   - 🌊 High-Rate DoS Telemetry Flooding
   - 🚫 Unauthorized Rogue Peer Injection
   - 💀 Sudden Node Crash / Disconnection (10s Sajid Eq. 4 Failover)
   - ♻️ Node Reboot & Re-join Swarm
   - 🚨 Manual Operator Backup Takeover
"""

import os
import sys
import time
import math
import json
import queue
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
from typing import Dict, Any, List, Optional

# Adjust module import path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from swarm_node import DecentralizedSwarmNode, WAYPOINT_COORDS
from protocol import MessageType, SwarmPacket

# Cyber Terminal Theme Palette
BG_WINDOW = "#070a0f"
BG_PANEL = "#0d131a"
BG_TERMINAL = "#05070a"
BG_HEADER = "#111923"
BORDER_DARK = "#1f2937"

# Accent Colors
CYBER_BLUE = "#38bdf8"
CYBER_GREEN = "#22c55e"
CYBER_PURPLE = "#c084fc"
CYBER_AMBER = "#fbbf24"
CYBER_RED = "#ef4444"
CYBER_ORANGE = "#fb923c"
CYBER_TEAL = "#2dd4bf"
TEXT_WHITE = "#f8fafc"
TEXT_MUTED = "#94a3b8"


class SwarmTerminalDashboard:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Decentralized PQC UAV Swarm — Multi-Terminal Control & Attack Console")
        self.root.geometry("1560x940")
        self.root.minsize(1280, 800)
        self.root.configure(bg=BG_WINDOW)

        # Thread-safe log message queue: (drone_id, formatted_text, tag)
        self.log_queue: queue.Queue = queue.Queue()

        # Swarm Node Instances: {"drone_1": DecentralizedSwarmNode, ...}
        self.nodes: Dict[str, DecentralizedSwarmNode] = {}
        self.target_drone_var = tk.StringVar(value="drone_2")
        self.is_running = False

        # Terminal UI Component References: {drone_id: {"text": ScrolledText, "entry": Entry, "status_lbl": Label, ...}}
        self.terminals: Dict[str, Dict[str, Any]] = {}

        self._build_ui()
        self._start_swarm_nodes()

        # Start background UI update loops
        self.root.after(50, self._process_log_queue)
        self.root.after(200, self._update_telemetry_headers)

    # ─────────────────────────────────────────────────────────────
    # UI Layout Construction
    # ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── 1. Top Master & Attack Toolbar ──
        top_bar = tk.Frame(self.root, bg=BG_HEADER, padx=12, pady=6, highlightbackground=BORDER_DARK, highlightthickness=1)
        top_bar.pack(fill=tk.X, side=tk.TOP)

        # Banner Title
        title_box = tk.Frame(top_bar, bg=BG_HEADER)
        title_box.pack(side=tk.LEFT, padx=5)

        tk.Label(
            title_box,
            text="🛰️ DECENTRALIZED PQC UAV SWARM TACTICAL TERMINALS",
            font=("Consolas", 12, "bold"),
            fg=CYBER_BLUE,
            bg=BG_HEADER
        ).pack(anchor="w")

        tk.Label(
            title_box,
            text="Zero-SPOF Peer Mesh | Hybrid ML-KEM + ECC | Mondrian Conformal AI IDS | Eq. 4 Backup Failover",
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_HEADER
        ).pack(anchor="w")

        # Attack Target Selector
        target_box = tk.LabelFrame(
            top_bar,
            text=" 🎯 Select Target Drone ",
            font=("Segoe UI", 8, "bold"),
            bg=BG_HEADER,
            fg=CYBER_AMBER,
            padx=6,
            pady=2
        )
        target_box.pack(side=tk.LEFT, padx=15)

        targets = [
            ("drone_1", "Drone 1 (Alpha)", CYBER_BLUE),
            ("drone_2", "Drone 2 (Bravo)", CYBER_GREEN),
            ("drone_3", "Drone 3 (Charlie)", CYBER_PURPLE),
            ("backup_drone", "Backup Drone", CYBER_ORANGE)
        ]

        for d_id, d_label, col in targets:
            rb = tk.Radiobutton(
                target_box,
                text=d_label,
                value=d_id,
                variable=self.target_drone_var,
                font=("Segoe UI", 8, "bold"),
                bg=BG_HEADER,
                fg=col,
                selectcolor=BG_TERMINAL,
                activebackground=BG_HEADER,
                activeforeground=col
            )
            rb.pack(side=tk.LEFT, padx=4)

        # Attack Action Buttons
        atk_btn_box = tk.Frame(top_bar, bg=BG_HEADER)
        atk_btn_box.pack(side=tk.LEFT, padx=10)

        # Attack 1: Spoofing
        btn_spoof = tk.Button(
            atk_btn_box,
            text="⚡ GPS Spoof Attack",
            bg="#b91c1c", fg="white", font=("Segoe UI", 8, "bold"),
            activebackground="#991b1b", activeforeground="white",
            relief=tk.FLAT, padx=6, pady=3,
            command=self._inject_spoof_attack
        )
        btn_spoof.pack(side=tk.LEFT, padx=3)

        # Attack 2: Replay
        btn_replay = tk.Button(
            atk_btn_box,
            text="🔄 Replay Attack",
            bg="#c2410c", fg="white", font=("Segoe UI", 8, "bold"),
            activebackground="#9a3412", activeforeground="white",
            relief=tk.FLAT, padx=6, pady=3,
            command=self._inject_replay_attack
        )
        btn_replay.pack(side=tk.LEFT, padx=3)

        # Attack 3: DoS Flood
        btn_flood = tk.Button(
            atk_btn_box,
            text="🌊 DoS Flooding",
            bg="#7e22ce", fg="white", font=("Segoe UI", 8, "bold"),
            activebackground="#6b21a8", activeforeground="white",
            relief=tk.FLAT, padx=6, pady=3,
            command=self._inject_flood_attack
        )
        btn_flood.pack(side=tk.LEFT, padx=3)

        # Attack 4: Rogue Peer
        btn_rogue = tk.Button(
            atk_btn_box,
            text="🚫 Rogue Node",
            bg="#374151", fg="white", font=("Segoe UI", 8, "bold"),
            activebackground="#1f2937", activeforeground="white",
            relief=tk.FLAT, padx=6, pady=3,
            command=self._inject_unauthorized_node
        )
        btn_rogue.pack(side=tk.LEFT, padx=3)

        # Node Crash / Reboot controls
        btn_kill = tk.Button(
            atk_btn_box,
            text="💀 Crash / Kill",
            bg="#7f1d1d", fg="white", font=("Segoe UI", 8, "bold"),
            activebackground="#450a0a", activeforeground="white",
            relief=tk.FLAT, padx=6, pady=3,
            command=self._kill_selected_node
        )
        btn_kill.pack(side=tk.LEFT, padx=3)

        btn_reboot = tk.Button(
            atk_btn_box,
            text="♻️ Reboot Node",
            bg="#15803d", fg="white", font=("Segoe UI", 8, "bold"),
            activebackground="#166534", activeforeground="white",
            relief=tk.FLAT, padx=6, pady=3,
            command=self._reboot_selected_node
        )
        btn_reboot.pack(side=tk.LEFT, padx=3)

        btn_failover = tk.Button(
            atk_btn_box,
            text="🛡️ Force Backup",
            bg="#0369a1", fg="white", font=("Segoe UI", 8, "bold"),
            activebackground="#075985", activeforeground="white",
            relief=tk.FLAT, padx=6, pady=3,
            command=self._trigger_manual_backup_takeover
        )
        btn_failover.pack(side=tk.LEFT, padx=3)

        # Master Clear & Restart
        btn_clear_all = tk.Button(
            top_bar,
            text="🧹 Clear All",
            bg="#334155", fg="white", font=("Segoe UI", 8, "bold"),
            relief=tk.FLAT, padx=6, pady=3,
            command=self._clear_all_terminals
        )
        btn_clear_all.pack(side=tk.RIGHT, padx=4)

        # ── 2. 4-Terminal 2x2 Grid Container ──
        grid_container = tk.Frame(self.root, bg=BG_WINDOW)
        grid_container.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        grid_container.columnconfigure(0, weight=1)
        grid_container.columnconfigure(1, weight=1)
        grid_container.rowconfigure(0, weight=1)
        grid_container.rowconfigure(1, weight=1)

        terminal_configs = [
            ("drone_1", "📟 TERMINAL 1: UAV ALPHA (DRONE_1)", 0, 0, CYBER_BLUE),
            ("drone_2", "📟 TERMINAL 2: UAV BRAVO (DRONE_2)", 0, 1, CYBER_GREEN),
            ("drone_3", "📟 TERMINAL 3: UAV CHARLIE (DRONE_3)", 1, 0, CYBER_PURPLE),
            ("backup_drone", "📟 TERMINAL 4: AUTONOMOUS BACKUP (BACKUP_DRONE)", 1, 1, CYBER_ORANGE),
        ]

        for drone_id, title, r, c, accent_color in terminal_configs:
            t_frame = self._create_terminal_pane(grid_container, drone_id, title, accent_color)
            t_frame.grid(row=r, column=c, padx=4, pady=4, sticky="nsew")

    def _create_terminal_pane(self, parent, drone_id: str, title: str, accent_color: str) -> tk.Frame:
        """Constructs a dedicated terminal console pane with header telemetry bar and interactive input."""
        pane = tk.Frame(parent, bg=BG_PANEL, highlightbackground=BORDER_DARK, highlightthickness=1)

        # ── Terminal Top Header Bar ──
        header_bar = tk.Frame(pane, bg=BG_HEADER, padx=8, pady=4)
        header_bar.pack(fill=tk.X, side=tk.TOP)

        # Title Label
        tk.Label(
            header_bar,
            text=title,
            font=("Consolas", 9, "bold"),
            fg=accent_color,
            bg=BG_HEADER
        ).pack(side=tk.LEFT)

        # Status Badge
        lbl_status = tk.Label(
            header_bar,
            text="INITIALIZING",
            font=("Consolas", 8, "bold"),
            bg="#1e293b",
            fg="white",
            padx=5,
            pady=1
        )
        lbl_status.pack(side=tk.LEFT, padx=8)

        # PQC Security Level Badge
        lbl_pqc = tk.Label(
            header_bar,
            text="NODE: ML-KEM-512",
            font=("Consolas", 8, "bold"),
            bg="#064e3b",
            fg="white",
            padx=4,
            pady=1
        )
        lbl_pqc.pack(side=tk.LEFT, padx=4)

        # Battery / Coordinates Snapshot
        lbl_info = tk.Label(
            header_bar,
            text="Lat: 16.792406 | Lon: 80.819767 | Alt: 5.0m | Bat: 11.52V",
            font=("Consolas", 8),
            fg=TEXT_MUTED,
            bg=BG_HEADER
        )
        lbl_info.pack(side=tk.RIGHT, padx=4)

        # ── Dedicated Link & Trust Matrix Sub-header Ribbon ──
        link_ribbon = tk.Frame(pane, bg="#090d14", padx=8, pady=3, highlightbackground="#1e293b", highlightthickness=1)
        link_ribbon.pack(fill=tk.X, side=tk.TOP)

        tk.Label(
            link_ribbon,
            text="🔗 PEER LINKS & TRUST:",
            font=("Consolas", 8, "bold"),
            fg=CYBER_AMBER,
            bg="#090d14"
        ).pack(side=tk.LEFT, padx=(0, 6))

        lbl_links = tk.Label(
            link_ribbon,
            text="Initializing mesh links...",
            font=("Consolas", 8),
            fg=CYBER_TEAL,
            bg="#090d14"
        )
        lbl_links.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # ── Terminal Console Output Box ──
        console_frame = tk.Frame(pane, bg=BG_TERMINAL)
        console_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        txt_console = scrolledtext.ScrolledText(
            console_frame,
            bg=BG_TERMINAL,
            fg="#e2e8f0",
            font=("Consolas", 9),
            insertbackground=CYBER_GREEN,
            wrap=tk.WORD,
            state=tk.DISABLED,
            bd=0,
            highlightthickness=0
        )
        txt_console.pack(fill=tk.BOTH, expand=True)

        # Terminal Color Tag Styling
        txt_console.tag_config("INFO", foreground="#94a3b8")
        txt_console.tag_config("PQC", foreground="#c084fc", font=("Consolas", 9, "bold"))
        txt_console.tag_config("TELEM", foreground="#4ade80")
        txt_console.tag_config("RECV", foreground="#38bdf8")
        txt_console.tag_config("ALERT", foreground="#f87171", font=("Consolas", 9, "bold"))
        txt_console.tag_config("WARN", foreground="#fbbf24", font=("Consolas", 9, "bold"))
        txt_console.tag_config("TAKEOVER", foreground="#fb923c", font=("Consolas", 9, "bold"))
        txt_console.tag_config("NAV", foreground="#2dd4bf")
        txt_console.tag_config("CMD", foreground="#fef08a", font=("Consolas", 9, "bold"))
        txt_console.tag_config("SUCCESS", foreground="#22c55e", font=("Consolas", 9, "bold"))

        # ── Terminal Bottom Interactive Command Prompt ──
        cmd_bar = tk.Frame(pane, bg=BG_HEADER, padx=6, pady=3)
        cmd_bar.pack(fill=tk.X, side=tk.BOTTOM)

        prompt_lbl = tk.Label(
            cmd_bar,
            text=f"[{drone_id}] >",
            font=("Consolas", 9, "bold"),
            fg=CYBER_GREEN,
            bg=BG_HEADER
        )
        prompt_lbl.pack(side=tk.LEFT, padx=2)

        entry_cmd = tk.Entry(
            cmd_bar,
            bg=BG_TERMINAL,
            fg="#f8fafc",
            font=("Consolas", 9),
            insertbackground="white",
            relief=tk.FLAT,
            highlightbackground=BORDER_DARK,
            highlightthickness=1
        )
        entry_cmd.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)

        # Enter key triggers command execution
        entry_cmd.bind("<Return>", lambda event, d=drone_id: self._on_execute_command(d))

        btn_send = tk.Button(
            cmd_bar,
            text="EXEC",
            font=("Consolas", 8, "bold"),
            bg="#1e293b",
            fg=CYBER_BLUE,
            activebackground="#334155",
            activeforeground="white",
            relief=tk.FLAT,
            padx=6,
            pady=1,
            command=lambda d=drone_id: self._on_execute_command(d)
        )
        btn_send.pack(side=tk.RIGHT)

        btn_clear = tk.Button(
            cmd_bar,
            text="CLR",
            font=("Consolas", 8),
            bg="#111827",
            fg=TEXT_MUTED,
            activebackground="#1f2937",
            activeforeground="white",
            relief=tk.FLAT,
            padx=4,
            pady=1,
            command=lambda d=drone_id: self._clear_terminal(d)
        )
        btn_clear.pack(side=tk.RIGHT, padx=2)

        # Store component references
        self.terminals[drone_id] = {
            "text": txt_console,
            "entry": entry_cmd,
            "status_lbl": lbl_status,
            "pqc_lbl": lbl_pqc,
            "info_lbl": lbl_info,
            "link_lbl": lbl_links
        }

        return pane

    # ─────────────────────────────────────────────────────────────
    # Swarm Node Launch & Logging Pipeline
    # ─────────────────────────────────────────────────────────────

    def _start_swarm_nodes(self):
        """Spawns the 4 DecentralizedSwarmNode instances with real-time log piping."""
        self.is_running = True

        def log_sink(node_id: str, formatted_msg: str, tag: str):
            self.log_queue.put((node_id, formatted_msg, tag))

        d1 = DecentralizedSwarmNode(node_id="drone_1", role="primary", frequency_hz=2.0, log_callback=log_sink)
        d2 = DecentralizedSwarmNode(node_id="drone_2", role="primary", frequency_hz=2.0, log_callback=log_sink)
        d3 = DecentralizedSwarmNode(node_id="drone_3", role="primary", frequency_hz=2.0, log_callback=log_sink)
        backup = DecentralizedSwarmNode(node_id="backup_drone", role="backup", frequency_hz=2.0, log_callback=log_sink)

        self.nodes = {
            "drone_1": d1,
            "drone_2": d2,
            "drone_3": d3,
            "backup_drone": backup
        }

        for node_id, n in self.nodes.items():
            n.start()
            self._write_to_terminal(node_id, f"[*] Initialized Swarm Node '{node_id}' (Role: {n.role.upper()})", tag="SUCCESS")
            self._write_to_terminal(node_id, f"[*] Type 'help' in prompt below to see available live commands.\n", tag="INFO")

    def _process_log_queue(self):
        """Pulls logs from the background queue and prints them into the appropriate drone terminal."""
        while not self.log_queue.empty():
            try:
                node_id, msg, tag = self.log_queue.get_nowait()
                self._write_to_terminal(node_id, msg, tag)
            except queue.Empty:
                break
            except Exception:
                pass

        if self.is_running:
            self.root.after(40, self._process_log_queue)

    def _write_to_terminal(self, drone_id: str, msg: str, tag: str = "INFO"):
        """Thread-safe terminal text append."""
        if drone_id not in self.terminals:
            return

        txt_widget = self.terminals[drone_id]["text"]
        txt_widget.config(state=tk.NORMAL)
        txt_widget.insert(tk.END, f"{msg}\n", tag)
        txt_widget.see(tk.END)
        txt_widget.config(state=tk.DISABLED)

    def _update_telemetry_headers(self):
        """Updates header badges (Status, Battery, PQC level, GPS) and Peer Links Ribbon on each terminal pane."""
        if not self.is_running:
            return

        for drone_id, node in self.nodes.items():
            if drone_id not in self.terminals:
                continue

            term = self.terminals[drone_id]
            is_alive = node.running

            if not is_alive:
                term["status_lbl"].config(text="OFFLINE / CRASHED", bg="#7f1d1d")
                term["info_lbl"].config(text="STATUS: DISCONNECTED | SILENT (10s FAILOVER TRIGGERED)")
                term["link_lbl"].config(text="ALL LINKS TERMINATED (OFFLINE)", fg="#ef4444")
                continue

            # Update Status Badge
            st = node.status
            if node.controller.is_isolated(drone_id):
                term["status_lbl"].config(text="QUARANTINED", bg="#dc2626")
            elif st == "LANDING":
                term["status_lbl"].config(text="LANDING ON SITE", bg="#d97706")
            elif st == "LANDED":
                term["status_lbl"].config(text="LANDED (DISARMED)", bg="#475569")
            elif st == "ACTIVE_BACKUP":
                term["status_lbl"].config(text=f"ACTIVE BACKUP -> {node.active_backup_target}", bg="#ea580c")
            elif st == "STANDBY":
                term["status_lbl"].config(text="STANDBY (EQ. 4)", bg="#334155")
            else:
                term["status_lbl"].config(text="FLYING (NOMINAL)", bg="#16a34a")

            # Update Max PQC Level in use with active peers
            max_lvl = 512
            common_peers = ["drone_1", "drone_2", "drone_3", "backup_drone"]
            link_segments = []

            for p_id in common_peers:
                if p_id != drone_id:
                    lvl = node.controller.get_kyber_level(p_id)
                    t_val = node.trust_mgr.get_trust(p_id)
                    alpha = round(max(0.0, min(1.0, 1.0 - t_val)), 2)
                    is_iso = node.controller.is_isolated(p_id)

                    with node.crypto_lock:
                        p_session = node.peer_sessions.get(p_id)

                    # Only active, non-quarantined, established peer links determine node security level
                    if not is_iso and p_session:
                        max_lvl = max(max_lvl, p_session.get("kyber_param", lvl))

                    short_p = p_id.replace("drone_", "D").replace("backup_drone", "BK")
                    if is_iso:
                        link_segments.append(f"{short_p}:[QUARANTINED T={t_val:.2f}]")
                    elif p_session:
                        link_segments.append(f"{short_p}:[T={t_val:.2f} | K-{lvl} | α={alpha:.2f}]")
                    else:
                        link_segments.append(f"{short_p}:[DISCOVERING T={t_val:.2f}]")

            pqc_color = "#064e3b" if max_lvl == 512 else ("#854d0e" if max_lvl == 768 else "#7f1d1d")
            term["pqc_lbl"].config(text=f"NODE: ML-KEM-{max_lvl}", bg=pqc_color)

            # Update GPS and Battery
            volt = node.battery_voltage
            term["info_lbl"].config(
                text=f"Lat: {node.lat:.6f} | Lon: {node.lon:.6f} | Alt: {node.alt:.1f}m | Bat: {volt:.2f}V"
            )

            # Update Dedicated Peer Links & Kyber Ribbon
            term["link_lbl"].config(text="   •   ".join(link_segments))

        self.root.after(250, self._update_telemetry_headers)

    # ─────────────────────────────────────────────────────────────
    # Interactive Terminal Command Parser
    # ─────────────────────────────────────────────────────────────

    def _on_execute_command(self, drone_id: str):
        """Processes CLI commands entered in the prompt of a specific drone terminal."""
        if drone_id not in self.terminals or drone_id not in self.nodes:
            return

        entry = self.terminals[drone_id]["entry"]
        cmd_str = entry.get().strip()
        entry.delete(0, tk.END)

        if not cmd_str:
            return

        # Echo command into terminal
        self._write_to_terminal(drone_id, f"[{drone_id}] > {cmd_str}", tag="CMD")

        node = self.nodes[drone_id]
        tokens = cmd_str.split()
        cmd = tokens[0].lower()

        if cmd == "help":
            self._write_to_terminal(drone_id, "Available Live Terminal Commands:", tag="INFO")
            self._write_to_terminal(drone_id, "  help                  - Show this help menu", tag="INFO")
            self._write_to_terminal(drone_id, "  status                - Print detailed kinematic & battery status", tag="INFO")
            self._write_to_terminal(drone_id, "  links / peers / trust - Display full PQC Peer Links, Kyber levels & Trust matrix", tag="INFO")
            self._write_to_terminal(drone_id, "  rekey <512|768|1024>  - Shift security ladder and rekey with active peers", tag="INFO")
            self._write_to_terminal(drone_id, "  handshake <peer_id>   - Initiate mutual hybrid PQC handshake with target peer", tag="INFO")
            self._write_to_terminal(drone_id, "  isolate <peer_id>     - Manually quarantine a peer node", tag="INFO")
            self._write_to_terminal(drone_id, "  battery <voltage>     - Inject simulated battery voltage (e.g. battery 10.15)", tag="INFO")
            self._write_to_terminal(drone_id, "  clear                 - Clear this terminal console output\n", tag="INFO")

        elif cmd == "status":
            self._write_to_terminal(drone_id, f"── NODE STATUS REPORT [{drone_id.upper()}] ──", tag="INFO")
            self._write_to_terminal(drone_id, f"  Role            : {node.role.upper()}", tag="INFO")
            self._write_to_terminal(drone_id, f"  Flight Status   : {node.status}", tag="INFO")
            self._write_to_terminal(drone_id, f"  Coordinates     : Lat={node.lat:.6f}, Lon={node.lon:.6f}, Alt={node.alt:.1f}m", tag="INFO")
            self._write_to_terminal(drone_id, f"  Waypoint Target : #{node.current_wp_idx+1} of {len(WAYPOINT_COORDS)}", tag="INFO")
            self._write_to_terminal(drone_id, f"  Battery Voltage : {node.battery_voltage:.3f}V (Cutoff: {node.battery_cutoff:.2f}V)", tag="INFO")
            self._write_to_terminal(drone_id, f"  Active Backup Target: {node.active_backup_target or 'None'}\n", tag="INFO")

        elif cmd in ("peers", "trust", "links"):
            self._write_to_terminal(drone_id, f"╔══════════════════════════════════════════════════════════════════════════════════╗", tag="PQC")
            self._write_to_terminal(drone_id, f"║       PQC LINK & TRUST MATRIX REPORT FOR [{drone_id.upper()}]                          ║", tag="PQC")
            self._write_to_terminal(drone_id, f"╠══════════════╦══════════╦══════════╦══════════════╦═════════════╦════════════════╣", tag="PQC")
            self._write_to_terminal(drone_id, f"║ PEER NODE    ║ TRUST(T) ║ ALPHA(α) ║ PQC PARAM    ║ LINK STATUS ║ CIPHER SUITE   ║", tag="PQC")
            self._write_to_terminal(drone_id, f"╠══════════════╬══════════╬══════════╬══════════════╬═════════════╬════════════════╣", tag="PQC")

            common_peers = ["drone_1", "drone_2", "drone_3", "backup_drone"]
            for p_id in common_peers:
                if p_id != drone_id:
                    t_val = node.trust_mgr.get_trust(p_id)
                    alpha = round(max(0.0, min(1.0, 1.0 - t_val)), 4)
                    lvl = node.controller.get_kyber_level(p_id)
                    is_iso = node.controller.is_isolated(p_id)

                    with node.crypto_lock:
                        p_session = node.peer_sessions.get(p_id)

                    if is_iso:
                        status_str = "QUARANTINED"
                        cipher_str = "BLOCKED"
                    elif p_session:
                        status_str = "ESTABLISHED"
                        cipher_str = "AES-256-GCM"
                    else:
                        status_str = "STANDBY"
                        cipher_str = "PENDING"

                    self._write_to_terminal(
                        drone_id,
                        f"║ {p_id:<12} ║  {t_val:.4f}  ║  {alpha:.4f}  ║ ML-KEM-{lvl:<5} ║ {status_str:<11} ║ {cipher_str:<14} ║",
                        tag="PQC"
                    )

            self._write_to_terminal(drone_id, f"╚══════════════╩══════════╩══════════╩══════════════╩═════════════╩════════════════╝\n", tag="PQC")

        elif cmd == "rekey":
            if len(tokens) < 2 or tokens[1] not in ["512", "768", "1024"]:
                self._write_to_terminal(drone_id, "Usage: rekey <512|768|1024> [peer_id]", tag="WARN")
                return
            new_level = int(tokens[1])
            target_peer = tokens[2] if len(tokens) > 2 else None
            if target_peer:
                node.controller.unquarantine_peer(target_peer)
                node._subscribe_peer(target_peer)
                node.initiate_pqc_handshake(target_peer, kyber_level=new_level)
                self._write_to_terminal(drone_id, f"Performing fresh PQC Key Establishment with {target_peer} -> ML-KEM-{new_level}...", tag="WARN")
            else:
                self._write_to_terminal(drone_id, f"Initiating manual rekey escalation to ML-KEM-{new_level} for all active peers...", tag="WARN")
                for p_id in ["drone_1", "drone_2", "drone_3", "backup_drone"]:
                    if p_id != drone_id and not node.controller.is_isolated(p_id):
                        node.initiate_pqc_handshake(p_id, kyber_level=new_level)

        elif cmd == "handshake":
            if len(tokens) < 2:
                self._write_to_terminal(drone_id, "Usage: handshake <peer_id>", tag="WARN")
                return
            target_peer = tokens[1]
            if node.controller.is_isolated(target_peer):
                node.controller.unquarantine_peer(target_peer)
                node._subscribe_peer(target_peer)
            self._write_to_terminal(drone_id, f"Sending PQC handshake init to {target_peer}...", tag="PQC")
            node.initiate_pqc_handshake(target_peer)

        elif cmd == "isolate":
            if len(tokens) < 2:
                self._write_to_terminal(drone_id, "Usage: isolate <peer_id>", tag="WARN")
                return
            target_peer = tokens[1]
            node.quarantine_peer(target_peer, reason="Manual operator command")
            self._write_to_terminal(drone_id, f"Peer '{target_peer}' isolated: Keys revoked, MQTT unsubscribed, communication blocked.", tag="ALERT")

        elif cmd == "battery":
            if len(tokens) < 2:
                self._write_to_terminal(drone_id, "Usage: battery <voltage>", tag="WARN")
                return
            try:
                v = float(tokens[1])
                node.battery_voltage = v
                self._write_to_terminal(drone_id, f"Simulated battery voltage updated to {v:.2f}V", tag="SUCCESS")
            except ValueError:
                self._write_to_terminal(drone_id, "Invalid voltage value.", tag="WARN")

        elif cmd in ("b", "backup", "land"):
            self._write_to_terminal(
                drone_id,
                f"🚨 OPERATOR 'b' INITIATED: {drone_id.upper()} descending for on-site landing & handing mission over to Backup Drone!",
                tag="TAKEOVER"
            )
            node.trigger_emergency_land_and_backup(reason="Operator 'b' command emergency landing")

        elif cmd == "clear":
            self._clear_terminal(drone_id)

        else:
            self._write_to_terminal(drone_id, f"Unknown command: '{cmd}'. Type 'help' for valid commands.", tag="WARN")

    def _clear_terminal(self, drone_id: str):
        if drone_id in self.terminals:
            txt_widget = self.terminals[drone_id]["text"]
            txt_widget.config(state=tk.NORMAL)
            txt_widget.delete("1.0", tk.END)
            txt_widget.config(state=tk.DISABLED)

    def _clear_all_terminals(self):
        for d_id in self.terminals.keys():
            self._clear_terminal(d_id)

    # ─────────────────────────────────────────────────────────────
    # Attack & Fault Injection Handlers (Universal Multi-Drone)
    # ─────────────────────────────────────────────────────────────

    def _inject_spoof_attack(self):
        target = self.target_drone_var.get()
        self._write_to_terminal(
            target,
            f"\n╔═══════════════════════════════════════════════════════════════════╗\n"
            f"║ 🎯 ATTACK INJECTION: GPS SPOOFING INTRUSION                      ║\n"
            f"║ Target Drone    : {target.upper():<47} ║\n"
            f"║ Injected Fault  : Erratic Lat/Lon Coordinate Jumps (>45 m/s)      ║\n"
            f"║ Expected Action : Peer AI IDS Anomaly Flag -> Kyber Escalation    ║\n"
            f"╚═══════════════════════════════════════════════════════════════════╝",
            tag="ALERT"
        )
        script_path = os.path.join(os.path.dirname(__file__), "attacks", "spoof_attack.py")
        subprocess.Popen([sys.executable, script_path, "--attacker-id", target, "--count", "12"])

    def _inject_replay_attack(self):
        target = self.target_drone_var.get()
        self._write_to_terminal(
            target,
            f"\n╔═══════════════════════════════════════════════════════════════════╗\n"
            f"║ 🎯 ATTACK INJECTION: CRYPTOGRAPHIC PACKET REPLAY                 ║\n"
            f"║ Target Drone    : {target.upper():<47} ║\n"
            f"║ Injected Vector : Stale Timestamp & Non-Monotonic Sequence Replay║\n"
            f"║ Expected Action : Anti-Replay Drop & PQC Security Ladder Rekey    ║\n"
            f"╚═══════════════════════════════════════════════════════════════════╝",
            tag="WARN"
        )
        script_path = os.path.join(os.path.dirname(__file__), "attacks", "replay_attack.py")
        subprocess.Popen([sys.executable, script_path, "--target-drone", target])

    def _inject_flood_attack(self):
        target = self.target_drone_var.get()
        self._write_to_terminal(
            target,
            f"\n╔═══════════════════════════════════════════════════════════════════╗\n"
            f"║ 🎯 ATTACK INJECTION: HIGH-RATE DoS TELEMETRY FLOODING            ║\n"
            f"║ Target Drone    : {target.upper():<47} ║\n"
            f"║ Injected Rate   : >50 msgs/sec High-Volume Telemetry Burst        ║\n"
            f"║ Expected Action : AI IDS RPS Limit Trigger -> Buffer Protection  ║\n"
            f"╚═══════════════════════════════════════════════════════════════════╝",
            tag="WARN"
        )
        script_path = os.path.join(os.path.dirname(__file__), "attacks", "flooding_attack.py")
        subprocess.Popen([sys.executable, script_path, "--target-drone", target, "--count", "200"])

    def _inject_unauthorized_node(self):
        for d_id in self.terminals.keys():
            self._write_to_terminal(
                d_id,
                f"\n╔═══════════════════════════════════════════════════════════════════╗\n"
                f"║ 🚨 ATTACK INJECTION: UNAUTHORIZED ROGUE NODE INTRUSION            ║\n"
                f"║ Rogue Node ID   : fake_drone_99                                   ║\n"
                f"║ Attack Vector   : Transmission without valid PQC / ECC credentials║\n"
                f"║ Expected Action : Connection Refused & Handshake Access Blocked   ║\n"
                f"╚═══════════════════════════════════════════════════════════════════╝",
                tag="ALERT"
            )
        script_path = os.path.join(os.path.dirname(__file__), "attacks", "unauthorized_peer.py")
        subprocess.Popen([sys.executable, script_path, "--fake-id", "fake_drone_99"])

    def _kill_selected_node(self):
        target = self.target_drone_var.get()
        if target in self.nodes and self.nodes[target].running:
            self.nodes[target].stop()
            self._write_to_terminal(
                target,
                f"\n╔═══════════════════════════════════════════════════════════════════╗\n"
                f"║ 💀 FAULT INJECTION: NODE TERMINATION / CRASH                      ║\n"
                f"║ Target Drone    : {target.upper():<47} ║\n"
                f"║ Expected Action : 10s Silent Timeout Failover (Sajid et al. Eq. 4)║\n"
                f"║ Swarm Reaction  : Autonomous Backup Drone Assumes Waypoint Mission║\n"
                f"╚═══════════════════════════════════════════════════════════════════╝",
                tag="ALERT"
            )
            # Notify other nodes
            for d_id in self.terminals.keys():
                if d_id != target:
                    self._write_to_terminal(d_id, f"[*] Lost heartbeat from {target.upper()} (monitoring silent failure timeout)...", tag="WARN")

    def _reboot_selected_node(self):
        target = self.target_drone_var.get()
        if target in self.nodes and not self.nodes[target].running:
            role = "backup" if target == "backup_drone" else "primary"
            def log_sink(nid: str, formatted_msg: str, tag: str):
                self.log_queue.put((nid, formatted_msg, tag))

            # Unquarantine on all active peers and re-subscribe MQTT
            for other_id, other_node in self.nodes.items():
                if other_id != target and other_node.running:
                    other_node.controller.unquarantine_peer(target)
                    other_node._subscribe_peer(target)

            new_node = DecentralizedSwarmNode(node_id=target, role=role, frequency_hz=2.0, log_callback=log_sink)
            self.nodes[target] = new_node
            new_node.start()
            self._write_to_terminal(target, f"\n♻️ [NODE RESTORE] {target.upper()} REBOOTED & RE-JOINING SWARM PQC MESH!", tag="SUCCESS")

            # If backup drone was standing in for this node, return backup to standby
            backup_node = self.nodes.get("backup_drone")
            if backup_node and backup_node.running and backup_node.status == "ACTIVE_BACKUP" and backup_node.active_backup_target == target:
                backup_node.status = "STANDBY"
                backup_node.active_backup_target = None
                self._write_to_terminal("backup_drone", f"[*] {target.upper()} back online. Backup Drone returned to STANDBY monitor.", tag="NAV")

            # Asynchronously trigger immediate PQC Rekey / Key-Establishment with all living peers
            def _mesh_rekey_worker():
                time.sleep(0.4)
                for other_id, other_node in list(self.nodes.items()):
                    if other_id != target and other_node.running:
                        other_node.controller.unquarantine_peer(target)
                        other_node._subscribe_peer(target)
                        new_node.controller.unquarantine_peer(other_id)
                        new_node._subscribe_peer(other_id)
                        new_node.initiate_pqc_handshake(other_id, kyber_level=512)

            threading.Thread(target=_mesh_rekey_worker, daemon=True).start()

    def _trigger_manual_backup_takeover(self):
        target = self.target_drone_var.get()
        if target in self.nodes and self.nodes[target].running:
            target_node = self.nodes[target]
            target_node.trigger_emergency_land_and_backup(reason="Manual operator 'b' trigger")
            self._write_to_terminal(
                target,
                f"🚨 OPERATOR 'b' ACTION: {target.upper()} initiating on-site landing. Backup Drone assigned to assume mission!",
                tag="TAKEOVER"
            )
        else:
            backup_node = self.nodes.get("backup_drone")
            if backup_node and backup_node.running:
                backup_node._trigger_backup_takeover(target, "Manual operator dashboard override")
                self._write_to_terminal("backup_drone", f"🚨 MANUAL OVERRIDE: Backup Drone assumed mission of {target.upper()}!", tag="TAKEOVER")

    def _on_close(self):
        self.is_running = False
        for n in self.nodes.values():
            try:
                n.stop()
            except Exception:
                pass
        self.root.destroy()


def main():
    root = tk.Tk()
    app = SwarmTerminalDashboard(root)
    root.protocol("WM_DELETE_WINDOW", app._on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
