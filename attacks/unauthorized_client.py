"""
Unauthorized Client Access Attack Executable
Attempts socket connection without valid certificate credentials.
"""

import socket
import time
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

def run_unauthorized_attack(host: str = "127.0.0.1", port: int = 8000) -> None:
    print("[!] Launching Unauthorized Client Connection Attempt...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    raw_garbage = b"UNAUTHORIZED_RAW_SOCKET_PAYLOAD_WITHOUT_PQC_HEADER"
    sock.sendall(raw_garbage)
    print(" -> Injected unauthenticated raw payload into socket...")
    time.sleep(1.0)
    sock.close()
    print("[OK] Unauthorized client test finished.")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Unauthorized Client Access Executable")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Target Ground Station IP")
    parser.add_argument("--port", type=int, default=8000, help="Target Ground Station Port")
    args = parser.parse_args()

    run_unauthorized_attack(host=args.host, port=args.port)
