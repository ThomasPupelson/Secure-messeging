from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import os
from pathlib import Path
from typing import Tuple

DEFAULT_KEYS_DIR = Path("aes_keys")
KEY_FILENAME_TEMPLATE = "key_{:04d}.bin"


def _ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def generate_keys(n: int = 4000):
    """
    Legenerál n darab 256-bites AES kulcsot aes_keys mappába.
    """
    _ensure_dir(DEFAULT_KEYS_DIR)
    existing = sorted(DEFAULT_KEYS_DIR.glob("key_*.bin"))
    start_index = 1
    if existing:
        last_name = existing[-1].stem  # pl. key_0123
        last_index = int(last_name.split("_")[1])
        start_index = last_index + 1

    for i in range(start_index, start_index + n):
        fname = DEFAULT_KEYS_DIR / KEY_FILENAME_TEMPLATE.format(i)
        if not fname.exists():
            key = get_random_bytes(32)  # 256 bit kulcs
            with open(fname, "wb") as f:
                f.write(key)


def _get_first_key_path() -> Path:
    """
    Visszaadja a legelső elérhető kulcs fájl útvonalát.
    """
    existing = sorted(DEFAULT_KEYS_DIR.glob("key_*.bin"))
    if not existing:
        return None
    return existing[0]


def encrypt_next_key(msg: bytes) -> Tuple[bytes, str]:
    """
    Titkosítja a msg-et a legelső kulccsal (AES-256-EAX).
    Visszaadja: combined_bytes (nonce+tag+ciphertext) és a kulcs SHA-512 hash.
    """
    _ensure_dir(DEFAULT_KEYS_DIR)
    key_path = _get_first_key_path()
    if key_path is None:
        generate_keys(4000)
        key_path = _get_first_key_path()

    if key_path is None or not key_path.exists():
        raise RuntimeError("Nincs elérhető kulcs titkosításhoz!")

    with open(key_path, "rb") as f:
        key = f.read()
    if len(key) != 32:
        raise ValueError("AES kulcs hossza hibás (nem 256 bit)!")

    key_sha512 = hashlib.sha512(key).hexdigest()

    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg)
    nonce = cipher.nonce

    # töröljük a kulcsot
    try:
        os.remove(key_path)
    except Exception as e:
        raise RuntimeError(f"Hiba a kulcs törlésénél: {e}")

    combined = nonce + tag + ciphertext
    return combined, key_sha512


def decrypt_combined_next_key(combined_bytes: bytes) -> bytes:
    """
    Visszafejti a combined_bytes-ot (nonce+tag+ciphertext) a legelső kulccsal.
    MAC ellenőrzést nem végez.
    """
    _ensure_dir(DEFAULT_KEYS_DIR)
    key_path = _get_first_key_path()
    if key_path is None or not key_path.exists():
        raise RuntimeError("Nincs elérhető kulcs visszafejtéshez!")

    with open(key_path, "rb") as f:
        key = f.read()
    if len(key) != 32:
        raise ValueError("AES kulcs hossza hibás (nem 256 bit)!")

    nonce = combined_bytes[:16]
    # tag = combined_bytes[16:32]  # kihagyva (nem ellenőrizzük)
    ciphertext = combined_bytes[32:]

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)

    # töröljük a kulcsot
    try:
        os.remove(key_path)
    except Exception as e:
        raise RuntimeError(f"Hiba a kulcs törlésénél: {e}")

    return plaintext
