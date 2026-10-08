"""
key_encapsulation/crystalskyber.py
===================================
Exposes all three Kyber parameter sets for use by server and client.

  Kyber-512  : k=2  — NORMAL security level   (fastest)
  Kyber-768  : k=3  — ELEVATED security level  (balanced)
  Kyber-1024 : k=4  — HIGH / CRITICAL level    (strongest, PQ-safe)

Fixed sizes (for logging):
  Kyber-512  : pk=800B   ct=768B
  Kyber-768  : pk=1184B  ct=1088B
  Kyber-1024 : pk=1568B  ct=1568B
"""
from .kyber import Kyber512, Kyber768, Kyber1024

# ── Parameter-set metadata for logging ────────────────────────
KYBER_PARAMS = {
    512:  {"pk_size": 800,  "ct_size": 768,  "instance": Kyber512},
    768:  {"pk_size": 1184, "ct_size": 1088, "instance": Kyber768},
    1024: {"pk_size": 1568, "ct_size": 1568, "instance": Kyber1024},
}

# ── Default (Kyber-512) ────────────────────────────────────────

def generate_kyber_keypair(param: int = 512):
    inst = KYBER_PARAMS[param]["instance"]
    pk, sk = inst.keygen()
    return pk, sk

def encapsulate_kyber(public_key, param: int = 512):
    inst = KYBER_PARAMS[param]["instance"]
    c, shared_secret = inst.enc(public_key)
    return c, shared_secret

def decapsulate_kyber(ciphertext, secret_key, param: int = 512):
    inst = KYBER_PARAMS[param]["instance"]
    shared_secret = inst.dec(ciphertext, secret_key)
    return shared_secret

def pk_size(param: int = 512) -> int:
    return KYBER_PARAMS[param]["pk_size"]

def ct_size(param: int = 512) -> int:
    return KYBER_PARAMS[param]["ct_size"]
