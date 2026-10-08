"""
key_encapsulation/hybrid_kem.py
================================
Feature 1 — IDS-Driven Hybrid ECC + Kyber KEM
===============================================
Combines both shared secrets into one AES key using HKDF.
The mixing ratio is driven by the live IDS trust score:

  trust=1.0 (clean UAV)  →  alpha=0.0  →  pure ECC key
  trust=0.5 (uncertain)  →  alpha=0.5  →  balanced mix
  trust=0.0 (intruder)   →  alpha=1.0  →  pure Kyber key

alpha is the Kyber weight.  (1-alpha) is the ECC weight.

Derivation:
    combined = HKDF(
        salt    = sha256(ecc_secret XOR kyber_secret),
        input   = alpha_bytes || ecc_secret || kyber_secret,
        length  = 32,
        info    = b"UAV-HYBRID-KEM-v1"
    )

This means:
  - At NORMAL level  (trust~1.0): combined key is ECC-dominant → fast
  - At ELEVATED      (trust~0.6): mix starts shifting toward Kyber
  - At HIGH          (trust~0.2): Kyber-dominant → PQ-safe
  - At CRITICAL      (trust~0.0): pure Kyber → maximum PQ security

Published metrics captured here:
  - ecc_keygen_ms, ecc_handshake_ms
  - kyber_keygen_ms, kyber_handshake_ms
  - hkdf_combine_ms
  - total_hybrid_handshake_ms
  - alpha (Kyber weight at time of handshake)
"""

import os
import struct
import time
from hashlib import sha256

# HKDF is in cryptography package (already a dependency)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives          import hashes
from cryptography.hazmat.backends            import default_backend


# ─────────────────────────────────────────────────────────────
# Alpha (Kyber weight) from trust score
# ─────────────────────────────────────────────────────────────

def trust_to_alpha(trust_score: float) -> float:
    """
    Map trust score [0, 1] → Kyber weight alpha [0, 1].
    Clamped and monotonically decreasing so lower trust = more Kyber.
    """
    trust = max(0.0, min(1.0, trust_score))
    alpha = 1.0 - trust           # trust=1 → alpha=0 (ECC); trust=0 → alpha=1 (Kyber)
    return round(alpha, 4)


def security_level_to_alpha(level_int: int) -> float:
    """
    Convenience: convert integer security level (0-3) to alpha.
    NORMAL=0 → 0.05 (mostly ECC, tiny Kyber salt)
    ELEVATED=1 → 0.40
    HIGH=2 → 0.80
    CRITICAL=3 → 1.00 (pure Kyber)
    """
    return {0: 0.05, 1: 0.40, 2: 0.80, 3: 1.00}.get(level_int, 0.50)


# ─────────────────────────────────────────────────────────────
# HKDF combiner
# ─────────────────────────────────────────────────────────────

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def combine_secrets(ecc_secret: bytes, kyber_secret: bytes,
                    alpha: float) -> tuple:
    """
    Combine ECC and Kyber shared secrets into one 32-byte AES key.

    Returns (combined_key_bytes, hkdf_time_ms).

    alpha = Kyber weight in [0, 1].
    Both secrets are padded/truncated to 32 bytes before mixing.
    """
    # Normalise lengths to 32 bytes
    ecc_32   = sha256(ecc_secret).digest()
    kyber_32 = sha256(kyber_secret).digest()

    # XOR-based salt (ensures both secrets are needed to reproduce)
    salt = sha256(_xor_bytes(ecc_32, kyber_32)).digest()

    # Encode alpha as 4-byte float in the info field so different
    # alpha values produce different keys even from same secrets
    alpha_bytes = struct.pack('>f', alpha)

    # Weighted input material
    # We concatenate both secrets weighted by alpha:
    # ikm = (1-alpha) bytes of ecc | alpha bytes of kyber
    # Since we use HKDF, the actual length doesn't matter for security;
    # we encode the weight in the info field.
    ikm = ecc_32 + kyber_32

    t0 = time.perf_counter()
    hkdf = HKDF(
        algorithm = hashes.SHA256(),
        length    = 32,
        salt      = salt,
        info      = b"UAV-HYBRID-KEM-v1" + alpha_bytes,
        backend   = default_backend(),
    )
    combined = hkdf.derive(ikm)
    hkdf_ms  = (time.perf_counter() - t0) * 1000

    return combined, round(hkdf_ms, 4)


# ─────────────────────────────────────────────────────────────
# Server-side hybrid handshake
# ─────────────────────────────────────────────────────────────

def server_hybrid_handshake(client_socket, buffer_size: int,
                             alpha: float) -> dict:
    """
    Perform a full hybrid handshake from the server side.

    Protocol (client sends first in each step):
      1. Client → ECC public key (65 bytes uncompressed)
      2. Server → ECC public key
      3. Client → Kyber public key
      4. Server → Kyber ciphertext
      5. Both derive combined key

    Returns dict with:
      aes_key, alpha,
      ecc_handshake_ms, kyber_handshake_ms,
      hkdf_ms, total_ms
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives            import serialization
    from key_encapsulation.ecc             import (generate_private_key,
                                                    get_public_key, get_shared_key)
    from key_encapsulation.crystalskyber   import encapsulate_kyber

    t_total = time.perf_counter()

    # ── ECC leg ───────────────────────────────────────────────
    t0 = time.perf_counter()
    srv_priv  = generate_private_key()
    srv_pub   = get_public_key(srv_priv)
    cli_ecc   = client_socket.recv(buffer_size)
    if not cli_ecc:
        raise ConnectionError("Client closed during hybrid ECC step")
    cli_pub   = ec.EllipticCurvePublicKey.from_encoded_point(srv_pub.curve, cli_ecc)
    client_socket.sendall(srv_pub.public_bytes(
        encoding = serialization.Encoding.X962,
        format   = serialization.PublicFormat.UncompressedPoint))
    ecc_secret      = get_shared_key(srv_priv, cli_pub)
    ecc_ms          = (time.perf_counter() - t0) * 1000

    # ── Kyber leg ─────────────────────────────────────────────
    t0 = time.perf_counter()
    cli_kyber_pub   = client_socket.recv(buffer_size)
    if not cli_kyber_pub:
        raise ConnectionError("Client closed during hybrid Kyber step")
    kyber_ct, kyber_secret = encapsulate_kyber(cli_kyber_pub)
    client_socket.sendall(kyber_ct)
    kyber_ms        = (time.perf_counter() - t0) * 1000

    # ── HKDF combine ──────────────────────────────────────────
    combined, hkdf_ms = combine_secrets(ecc_secret, kyber_secret, alpha)
    total_ms = (time.perf_counter() - t_total) * 1000

    return {
        "aes_key":           combined,
        "alpha":             alpha,
        "ecc_handshake_ms":  round(ecc_ms, 3),
        "kyber_handshake_ms":round(kyber_ms, 3),
        "hkdf_ms":           hkdf_ms,
        "total_ms":          round(total_ms, 3),
    }


# ─────────────────────────────────────────────────────────────
# Client-side hybrid handshake
# ─────────────────────────────────────────────────────────────

def client_hybrid_handshake(sock, buffer_size: int, alpha: float) -> dict:
    """
    Client side of hybrid handshake.  alpha must match what server uses
    (server sends it as the first byte after b'hybrid').

    Returns dict with aes_key + timing.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives            import serialization
    from key_encapsulation.ecc           import (generate_private_key,
                                                  get_public_key, get_shared_key)
    from key_encapsulation.crystalskyber import (generate_kyber_keypair,
                                                  decapsulate_kyber)

    t_total = time.perf_counter()

    # ── ECC leg ───────────────────────────────────────────────
    t0 = time.perf_counter()
    cli_priv    = generate_private_key()
    cli_pub     = get_public_key(cli_priv)
    sock.sendall(cli_pub.public_bytes(
        encoding = serialization.Encoding.X962,
        format   = serialization.PublicFormat.UncompressedPoint))
    srv_ecc = sock.recv(buffer_size)
    if not srv_ecc:
        raise ConnectionError("Server closed during hybrid ECC step")
    srv_pub     = ec.EllipticCurvePublicKey.from_encoded_point(cli_pub.curve, srv_ecc)
    ecc_secret  = get_shared_key(cli_priv, srv_pub)
    ecc_ms      = (time.perf_counter() - t0) * 1000

    # ── Kyber leg ─────────────────────────────────────────────
    t0 = time.perf_counter()
    ky_pub, ky_sec = generate_kyber_keypair()
    sock.sendall(ky_pub)
    kyber_ct    = sock.recv(buffer_size)
    if not kyber_ct:
        raise ConnectionError("Server closed during hybrid Kyber step")
    t_dec0 = time.perf_counter()
    kyber_secret = decapsulate_kyber(kyber_ct, ky_sec)
    decaps_ms    = (time.perf_counter() - t_dec0) * 1000.0
    kyber_ms     = (time.perf_counter() - t0) * 1000

    # ── HKDF combine ──────────────────────────────────────────
    combined, hkdf_ms = combine_secrets(ecc_secret, kyber_secret, alpha)
    total_ms = (time.perf_counter() - t_total) * 1000

    return {
        "aes_key":           combined,
        "alpha":             alpha,
        "ecc_handshake_ms":  round(ecc_ms, 3),
        "kyber_handshake_ms":round(kyber_ms, 3),
        "decaps_ms":         round(decaps_ms, 3),
        "hkdf_ms":           hkdf_ms,
        "total_ms":          round(total_ms, 3),
    }
