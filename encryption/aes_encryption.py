from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import struct

AES_KEY_LENGTH = 32  # 32 bytes = 256 bits


def generate_aes_key(shared_key):
    return shared_key[:AES_KEY_LENGTH]


def encrypt_data(plaintext, aes_key):
    nonce = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    # print(f'Nonce: {nonce}, Tag: {tag}')
    return nonce + tag + ciphertext


def decrypt_data(ciphertext, aes_key):
    nonce = ciphertext[:16]
    tag = ciphertext[16:32]
    ciphertext = ciphertext[32:]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    # print(f'Nonce: {nonce}, Tag: {tag}')
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError as e:
        print(f"Invalid ciphertext or tag {e}")
        return b""


def send_encrypted(sock, plaintext, aes_key, lock=None):
    """
    Encrypts plaintext and sends it over the socket with a 4-byte length prefix.
    If a lock is provided, the write operation is serialized.
    """
    ciphertext = encrypt_data(plaintext, aes_key)
    length = len(ciphertext)
    header = struct.pack('>I', length)
    payload = header + ciphertext
    if lock:
        with lock:
            sock.sendall(payload)
    else:
        sock.sendall(payload)


def recv_exactly(sock, num_bytes):
    """
    Guarantees reading exactly num_bytes across TCP fragments.
    Raises ConnectionError if the socket closes prematurely.
    """
    buf = b''
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed prematurely")
        buf += chunk
    return buf


def recv_encrypted(sock, aes_key):
    """
    Reads a length-prefixed encrypted message and returns the decrypted plaintext.
    Returns None on decryption failure.
    Returns b"" if the socket closes or fails.
    """
    try:
        length_bytes = recv_exactly(sock, 4)
        length = struct.unpack('>I', length_bytes)[0]
        ciphertext = recv_exactly(sock, length)
        decrypted = decrypt_data(ciphertext, aes_key)
        if decrypted == b"" and length > 0:
            return None
        return decrypted
    except (ConnectionError, OSError):
        return b""

