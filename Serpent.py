from pyserpent import Serpent
from Crypto.Random import get_random_bytes
import hashlib
import os
from pathlib import Path
from typing import Tuple

DEFAULT_KEYS_DIR = Path("serpent_keys")
KEY_FILENAME_TEMPLATE = "key_{:04d}.bin"


def _ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def generate_keys_Serpent(n: int = 4000):
    """
    Legenerál n darab kulcsot serpent_keys mappába.
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
            key = get_random_bytes(32)  # 256 bit
            with open(fname, "wb") as f:
                f.write(key)


def _get_first_key_path() -> Path:
    """
    Visszaadja a legelső elérhető kulcs fájlt.
    """
    existing = sorted(DEFAULT_KEYS_DIR.glob("key_*.bin"))
    if not existing:
        return None
    return existing[0]


def encrypt_next_key_Serpent(msg: bytes) -> Tuple[bytes, str]:
    """
    Titkosítás: mindig a legelső kulcsot használja.
    """
    _ensure_dir(DEFAULT_KEYS_DIR)
    key_path = _get_first_key_path()
    if key_path is None:
        generate_keys_Serpent(4000)
        key_path = _get_first_key_path()

    if key_path is None or not key_path.exists():
        raise RuntimeError("Nincs elérhető kulcs titkosításhoz!")

    with open(key_path, "rb") as f:
        key = f.read()
    key_sha512 = hashlib.sha512(key).hexdigest()

    # Padding 16 bájtos blokkokhoz
    pad_len = 16 - (len(msg) % 16)
    padded_msg = msg + bytes([pad_len]) * pad_len

    cipher = Serpent(key[:32])
    cipher_text = b''
    for i in range(0, len(padded_msg), 16):
        block = padded_msg[i:i+16]
        cipher_text += cipher.encrypt(block)

    # kulcs törlés
    try:
        os.remove(key_path)
    except Exception as e:
        raise RuntimeError(f"Hiba a kulcs törlésénél: {e}")

    return cipher_text, key_sha512


def decrypt_combined_next_key_Serpent(ciphertext: bytes) -> bytes:
    """
    Visszafejtés: mindig a legelső kulcsot használja.
    """
    _ensure_dir(DEFAULT_KEYS_DIR)
    key_path = _get_first_key_path()
    if key_path is None or not key_path.exists():
        raise RuntimeError("Nincs elérhető kulcs visszafejtéshez!")

    with open(key_path, "rb") as f:
        key = f.read()

    cipher = Serpent(key[:32])
    decrypted = b''
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted += cipher.decrypt(block)

    pad_len = decrypted[-1]
    plaintext = decrypted[:-pad_len]

    # kulcs törlés
    try:
        os.remove(key_path)
    except Exception as e:
        raise RuntimeError(f"Hiba a kulcs törlésénél: {e}")

    return plaintext
