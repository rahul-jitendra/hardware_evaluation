"""
broker_server.py — Local MQTT Mesh Broker Daemon with Live Transmission Logging
================================================================================
Paper: Ground Station-Free UAV Communication Architecture for Secure Connectivity
       and Autonomous Mission Continuity (IEEE Access, 2026)

Features:
- Live real-time logging of all incoming/outgoing MQTT telemetry messages, PQC handshakes, and alerts
- Formatted client connection, subscription, and packet size tracking
- Zero-configuration decentralized mesh broker
"""

import sys
import time
import json
import asyncio
import warnings
import argparse
from datetime import datetime

warnings.filterwarnings("ignore", category=DeprecationWarning)
from amqtt.broker import Broker, BrokerEvents
from amqtt.plugins.base import BasePlugin


class VerboseBrokerLoggerPlugin(BasePlugin):
    """Real-time live logger that prints all client connections, subscriptions, and message transmissions."""
    def __init__(self, context):
        super().__init__(context)
        self.msg_count = 0
        self.start_time = time.time()

    async def on_broker_client_connected(self, *args, **kwargs):
        session = kwargs.get('session')
        cid = kwargs.get('client_id') or getattr(session, 'client_id', None) or 'Anonymous / Initializing'
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{ts}] [BROKER CONNECT] (+) New client connected: '{cid}'", flush=True)

    async def on_broker_client_disconnected(self, *args, **kwargs):
        session = kwargs.get('session')
        cid = kwargs.get('client_id') or getattr(session, 'client_id', None) or 'Client'
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{ts}] [BROKER DISCONN] (-) Client disconnected: '{cid}'", flush=True)

    async def on_broker_client_subscribed(self, *args, **kwargs):
        cid = kwargs.get('client_id', 'unknown')
        topic = kwargs.get('topic', '')
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{ts}] [BROKER SUB]     (~) Client '{cid}' subscribed to topic: '{topic}'", flush=True)

    async def on_broker_client_unsubscribed(self, *args, **kwargs):
        cid = kwargs.get('client_id', 'unknown')
        topic = kwargs.get('topic', '')
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        print(f"[{ts}] [BROKER UNSUB]   (x) Client '{cid}' unsubscribed from: '{topic}'", flush=True)

    async def on_broker_message_received(self, *args, **kwargs):
        self.msg_count += 1
        message = kwargs.get('message')
        client_id = kwargs.get('client_id', 'anonymous')
        topic = getattr(message, 'topic', 'unknown')
        data = getattr(message, 'data', b'')
        size_bytes = len(data)
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # Format clean payload preview
        try:
            preview_str = data.decode('utf-8', errors='replace')
            parsed = json.loads(preview_str)
            if isinstance(parsed, dict):
                if "cipher_hex" in parsed:
                    preview_str = f"[PQC ENCRYPTED] Target={parsed.get('target_peer')}, Level=ML-KEM-{parsed.get('kyber_level')}, CipherHex={parsed['cipher_hex'][:24]}..."
                elif "lat" in parsed:
                    preview_str = f"Lat={parsed.get('lat')}, Lon={parsed.get('lon')}, Alt={parsed.get('alt')}m, Bat={parsed.get('voltage')}V, Status={parsed.get('status', 'FLYING')}"
                elif "plain_discovery" in parsed:
                    p = parsed["plain_discovery"]
                    preview_str = f"[DISCOVERY] ID={p.get('drone_id')}, Lat={p.get('lat')}, Lon={p.get('lon')}"
                else:
                    preview_str = json.dumps(parsed)[:90]
            else:
                preview_str = preview_str[:90]
        except Exception:
            preview_str = f"<binary {size_bytes} bytes>"

        print(f"[{ts}] [MSG #{self.msg_count:04d}] [{client_id}] -> Topic: '{topic}' ({size_bytes}B) | {preview_str}", flush=True)


def start_broker(host="0.0.0.0", port=1883):
    config = {
        'listeners': {
            'default': {
                'type': 'tcp',
                'bind': f'{host}:{port}'
            }
        },
        'plugins': {
            'amqtt.plugins.authentication.AnonymousAuthPlugin': {
                'allow_anonymous': True
            },
            'amqtt.plugins.sys.broker.BrokerSysPlugin': {
                'sys_interval': 30
            }
        }
    }

    print("=" * 80)
    print(f"   [UAV LOCAL MQTT MESH BROKER] RUNNING ON {host}:{port}")
    print("   Live packet transmission & peer connection monitoring ENABLED.")
    print("   Accepts local UAV nodes, remote peers (Tailscale / Wi-Fi), and GCS bridges.")
    print("=" * 80)

    async def run():
        broker = Broker(config)
        
        # Attach Live Message Logger Plugin
        logger_plugin = VerboseBrokerLoggerPlugin(broker.plugins_manager.app_context)
        broker.plugins_manager._plugins.append(logger_plugin)
        for event in list(BrokerEvents):
            if awaitable := getattr(logger_plugin, f"on_{event}", None):
                broker.plugins_manager._event_plugin_callbacks[event].append(awaitable)

        await broker.start()
        print(f"[*] Broker active and listening on port {port}. Press Ctrl+C to terminate.\n", flush=True)
        while True:
            await asyncio.sleep(3600)

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n[*] Broker stopped gracefully.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start Local UAV MQTT Broker with Live Message Logging")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Bind IP address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=1883, help="Bind port (default: 1883)")
    args = parser.parse_args()
    start_broker(args.host, args.port)
