from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import hashlib
import os
from pathlib import Path
from typing import Tuple

DEFAULT_KEYS_DIR = Path("chacha_keys")
KEY_FILENAME_TEMPLATE = "key_{:04d}.bin"


def _ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def generate_keys(n: int = 4000):
    """
    Legenerál n darab kulcsot chacha_keys mappába.
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


def encrypt_next_key_cha(msg: bytes) -> Tuple[bytes, str]:
    """
    Titkosítja a msg-et a legelső kulccsal.
    Visszaadja: nonce+ciphertext és kulcs SHA-512 hash.
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
    key_sha512 = hashlib.sha512(key).hexdigest()

    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ciphertext = cipher.encrypt(msg)

    # töröljük a kulcsot
    try:
        os.remove(key_path)
    except Exception as e:
        raise RuntimeError(f"Hiba a kulcs törlésénél: {e}")

    combined = nonce + ciphertext
    return combined, key_sha512


def decrypt_combined_next_key_cha(combined_bytes: bytes) -> bytes:
    """
    Visszafejti a combined_bytes (nonce+ciphertext) tartalmat a legelső kulccsal.
    """
    _ensure_dir(DEFAULT_KEYS_DIR)
    key_path = _get_first_key_path()
    if key_path is None or not key_path.exists():
        raise RuntimeError("Nincs elérhető kulcs visszafejtéshez!")

    with open(key_path, "rb") as f:
        key = f.read()

    nonce = combined_bytes[:12]
    ciphertext = combined_bytes[12:]

    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)

    # töröljük a kulcsot
    try:
        os.remove(key_path)
    except Exception as e:
        raise RuntimeError(f"Hiba a kulcs törlésénél: {e}")

    return plaintext
