import os
from pathlib import Path
from typing import Tuple
import hashlib

PAD_DIR = Path("one_time_pad")
PAD_FILE = PAD_DIR / "pad.bin"
PAD_SIZE = 500 * 1024 * 1024  # 500 MB

def _ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)

def _generate_pad():
    _ensure_dir(PAD_DIR)
    if not PAD_FILE.exists():
        print("Generating 500 MB one-time pad...")
        with open(PAD_FILE, "wb") as f:
            f.write(os.urandom(PAD_SIZE))
        print("Pad kész.")

def encrypt_next_key_OTP(msg: bytes, test_mode: bool = False) -> Tuple[bytes, bytes]:
    """
    One-time pad titkosítás.
    Visszaadja: ciphertext és a felhasznált pad byte sorozatot.
    Ha test_mode=True, a pad nem törlődik.
    """
    _generate_pad()
    with open(PAD_FILE, "rb") as f:
        pad = f.read(len(msg))

    ciphertext = bytes([b ^ pad[i] for i, b in enumerate(msg)])

    if not test_mode:
        # Töröljük a felhasznált pad elemeket
        with open(PAD_FILE, "rb+") as f:
            f.seek(len(msg))
            remaining = f.read()
            f.seek(0)
            f.write(remaining)
            f.truncate()

    return ciphertext, pad  # pad visszatérése bytes formában

def decrypt_combined_next_key_OTP(ciphertext: bytes, pad: bytes = None, test_mode: bool = False) -> bytes:
    """
    One-time pad visszafejtés.
    Ha pad meg van adva, azt használja, különben a pad elejéből olvas.
    """
    _generate_pad()
    if pad is None:
        with open(PAD_FILE, "rb") as f:
            pad = f.read(len(ciphertext))

    plaintext = bytes([b ^ pad[i] for i, b in enumerate(ciphertext)])

    if not test_mode and pad is None:
        # Töröljük a felhasznált pad elemeket
        with open(PAD_FILE, "rb+") as f:
            f.seek(len(ciphertext))
            remaining = f.read()
            f.seek(0)
            f.write(remaining)
            f.truncate()

    return plaintext
