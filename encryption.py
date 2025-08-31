import os
import ssl
import socket
import struct
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
import datetime
import hashlib
from cryptography.hazmat.primitives import padding
from AES_layer import generate_keys, encrypt_next_key, decrypt_combined_next_key
from chacha_layer import encrypt_next_key_cha, decrypt_combined_next_key_cha
from Serpent import encrypt_next_key_Serpent, decrypt_combined_next_key_Serpent
from QubitLayer import encrypt_next_key_OTP, decrypt_combined_next_key_OTP  # az előző OTP kód
import base64
import hmac
import tempfile
import json
import secrets
import logging
import signal
import sys
from typing import Optional, Tuple, Dict, Any
from contextlib import contextmanager
from collections import deque
import mmap
from pqc.kem import kyber512

from pqc.sign import dilithium2  # POST-QUANTUM SIGNATURE
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, constant_time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
import mimetypes
import zlib
import base64

TLS_CA_KEY_FILE = "tls_ca_key.pem"
TLS_CA_CERT_FILE = "tls_ca_cert.pem"
TLS_SERVER_CERT_FILE = "tls_server_cert.pem"
TLS_SERVER_KEY_FILE = "tls_server_key.pem"
TLS_CLIENT_CERT_FILE = "tls_client_cert.pem"
TLS_CLIENT_KEY_FILE = "tls_client_key.pem"

# Ed25519 keys
MY_PRIV_FILE = "my_sign_priv.pem"
MY_PUB_FILE = "my_sign_pub.pem"
PEER_CERT_FILE = "peer_pub.pem"

# Dilithium keys
MY_DILITHIUM_PRIV_FILE = "my_dilithium_priv.bin"
MY_DILITHIUM_PUB_FILE = "my_dilithium_pub.bin"
PEER_DILITHIUM_PUB_FILE = "peer_dilithium_pub.bin"

MY_CERT_FILE = "my_cert.info"
CERT_VALID_SECONDS = 365 * 24 * 3600

TLS_TRUSTED_CERTS_DIR = "trusted_tls_certs"
TLS_CERT_STORE = "tls_cert_store.json"
KEY_FINGERPRINTS_FILE = "key_fingerprints.json"

PAD_DEFAULT_SIZE = 500 * 1024 * 1024
PAD_CHUNK = 1 * 1024 * 1024
PAD_PATH_CFG = "pad_path.cfg"

REPLAY_WINDOW_SIZE = 10000
MAX_MESSAGE_SIZE = 64 * 1024
SESSION_TIMEOUT = 1800
CONNECTION_TIMEOUT = 60
MAX_CONNECTIONS_PER_IP = 3
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_MESSAGES = 100

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SecureError(Exception):
    pass


class CryptoError(SecureError):
    pass


class ProtocolError(SecureError):
    pass


class RateLimitError(SecureError):
    pass


def safe_fsync(file_obj):
    """Safely sync file to disk with Windows compatibility"""
    try:
        if hasattr(file_obj, 'fileno') and hasattr(file_obj, 'closed') and not file_obj.closed:
            file_obj.flush()
            os.fsync(file_obj.fileno())
    except (OSError, ValueError):
        pass


@contextmanager
def secure_file_operation(filepath: str, mode: str = 'r+b'):
    """Context manager for secure file operations with proper locking - Windows compatible"""
    lock_file = None

    try:
        lock_file = filepath + ".lock"

        for attempt in range(50):
            try:
                if not os.path.exists(lock_file):
                    with open(lock_file, 'w') as lf:
                        lf.write(str(os.getpid()))
                        lf.flush()
                        safe_fsync(lf)
                    break
                else:
                    try:
                        with open(lock_file, 'r') as lf:
                            pid = int(lf.read().strip())
                        if attempt > 25:
                            os.remove(lock_file)
                    except (ValueError, FileNotFoundError):
                        pass
            except OSError:
                if attempt == 49:
                    raise SecureError("Cannot acquire file lock")
                time.sleep(0.02)

        if not os.path.exists(filepath):
            with open(filepath, 'wb') as f:
                f.write(b'0')
                f.flush()
                safe_fsync(f)

        with open(filepath, mode) as f:
            yield f
            if not f.closed:
                f.flush()
                safe_fsync(f)

    finally:
        if lock_file and os.path.exists(lock_file):
            try:
                os.remove(lock_file)
            except OSError:
                pass


class SecureAtomicOperations:
    @staticmethod
    def atomic_write(filepath: str, data: bytes):
        """Atomic file write with proper permissions - Windows compatible"""
        dir_path = os.path.dirname(filepath) or "."

        with tempfile.NamedTemporaryFile(
                mode='wb',
                dir=dir_path,
                delete=False,
                prefix='.tmp_secure_',
                suffix='.tmp'
        ) as tmp_file:
            tmp_file.write(data)
            tmp_file.flush()
            safe_fsync(tmp_file)
            tmp_name = tmp_file.name

        try:
            os.chmod(tmp_name, 0o600)
        except OSError:
            pass

        if os.path.exists(filepath):
            os.remove(filepath)
        os.rename(tmp_name, filepath)

    @staticmethod
    def secure_delete(filepath: str):
        """Secure file deletion with overwriting - Windows compatible"""
        if not os.path.exists(filepath):
            return

        try:
            size = os.path.getsize(filepath)
            with open(filepath, "r+b") as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(secrets.token_bytes(size))
                    f.flush()
                    safe_fsync(f)
            os.remove(filepath)
        except Exception as e:
            logger.warning(f"Secure delete failed for {filepath}: {e}")


class RateLimiter:
    def __init__(self, max_requests: int = RATE_LIMIT_MAX_MESSAGES, window_seconds: int = RATE_LIMIT_WINDOW):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = deque()
        self.lock = threading.RLock()

    def allow_request(self) -> bool:
        with self.lock:
            now = time.time()
            while self.requests and self.requests[0] <= now - self.window_seconds:
                self.requests.popleft()
            if len(self.requests) >= self.max_requests:
                return False
            self.requests.append(now)
            return True


class ReplayProtection:
    def __init__(self, window_size: int = REPLAY_WINDOW_SIZE):
        self.seen_nonces = set()
        self.window_size = window_size
        self.sequence_number = 0
        self.lock = threading.RLock()
        self.last_cleanup = time.time()

    def validate_message(self, nonce: bytes, sequence: int) -> bool:
        with self.lock:
            if nonce in self.seen_nonces:
                raise ProtocolError("Replay attack detected - duplicate nonce")

            if sequence <= self.sequence_number - self.window_size:
                raise ProtocolError("Replay attack detected - old sequence number")

            self.seen_nonces.add(nonce)

            now = time.time()
            if now - self.last_cleanup > 300:
                self._cleanup_old_nonces()
                self.last_cleanup = now

            if sequence > self.sequence_number:
                self.sequence_number = sequence

            return True

    def _cleanup_old_nonces(self):
        if len(self.seen_nonces) > self.window_size * 2:
            old_nonces = list(self.seen_nonces)[:len(self.seen_nonces) - self.window_size]
            for old_nonce in old_nonces:
                self.seen_nonces.discard(old_nonce)


class SecurePadManager:
    def __init__(self, pad_path: str):
        if not os.path.exists(pad_path):
            raise FileNotFoundError(f"Pad file not found: {pad_path}")

        self.pad_path = pad_path
        self.offset_file = pad_path + ".offset"
        self.sequence_file = pad_path + ".sequence"
        self.checksum_file = pad_path + ".checksum"
        self.lock = threading.RLock()

        self._initialize_files()
        self._verify_pad_integrity()

    def _initialize_files(self):
        if not os.path.exists(self.offset_file):
            SecureAtomicOperations.atomic_write(self.offset_file, b'0')
        if not os.path.exists(self.sequence_file):
            SecureAtomicOperations.atomic_write(self.sequence_file, b'0')
        if not os.path.exists(self.checksum_file):
            checksum = self._calculate_pad_checksum()
            SecureAtomicOperations.atomic_write(self.checksum_file, checksum.encode())

    def _verify_pad_integrity(self):
        """Verify pad hasn't been tampered with"""
        try:
            with open(self.checksum_file, 'rb') as f:
                stored_checksum = f.read().decode().strip()

            current_checksum = self._calculate_pad_checksum()

            if not constant_time.bytes_eq(stored_checksum.encode(), current_checksum.encode()):
                raise CryptoError("Pad integrity check failed - possible tampering detected")

        except FileNotFoundError:
            pass

    def _calculate_pad_checksum(self) -> str:
        """Calculate secure checksum of the pad"""
        hasher = hashlib.sha3_256()
        with open(self.pad_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _get_offset(self) -> int:
        try:
            with secure_file_operation(self.offset_file, 'rb') as f:
                data = f.read().strip()
                return int(data or b'0')
        except Exception as e:
            logger.warning(f"Error getting offset: {e}")
            return 0

    def _get_sequence(self) -> int:
        try:
            with secure_file_operation(self.sequence_file, 'rb') as f:
                data = f.read().strip()
                return int(data or b'0')
        except Exception as e:
            logger.warning(f"Error getting sequence: {e}")
            return 0

    def _set_offset(self, val: int):
        if val < 0:
            raise ValueError("Offset cannot be negative")
        SecureAtomicOperations.atomic_write(self.offset_file, str(val).encode())

    def _set_sequence(self, val: int):
        if val < 0 or val > 0xFFFFFFFF:
            raise ValueError("Invalid sequence number")
        SecureAtomicOperations.atomic_write(self.sequence_file, str(val).encode())

    def prepare_send(self, message_length: int) -> Tuple[int, int, bytes]:
        if message_length <= 0 or message_length > MAX_MESSAGE_SIZE:
            raise ValueError("Invalid message length")

        with self.lock:
            offset = self._get_offset()
            sequence = self._get_sequence()

            if sequence >= 0xFFFFFFFF:
                raise CryptoError("Sequence number overflow - pad exhausted")

            size = os.path.getsize(self.pad_path)
            if offset + message_length > size:
                raise CryptoError("Insufficient pad remaining")

            with open(self.pad_path, "rb") as f:
                f.seek(offset)
                pad_data = f.read(message_length)
                if len(pad_data) != message_length:
                    raise CryptoError("Could not read required pad data")

            return offset, sequence, pad_data

    def confirm_send(self, message_length: int, old_offset: int, old_sequence: int):
        """Atomically confirm send operation"""
        with self.lock:
            current_offset = self._get_offset()
            current_sequence = self._get_sequence()

            if current_offset != old_offset or current_sequence != old_sequence:
                raise CryptoError("Pad state changed during operation")

            self._set_offset(old_offset + message_length)
            self._set_sequence(old_sequence + 1)

    def read_pad_data(self, offset: int, length: int) -> bytes:
        if offset < 0 or length <= 0 or length > MAX_MESSAGE_SIZE:
            raise ValueError("Invalid pad read parameters")

        size = os.path.getsize(self.pad_path)
        if offset + length > size:
            raise CryptoError("Pad read beyond bounds")

        with open(self.pad_path, "rb") as f:
            f.seek(offset)
            data = f.read(length)
            if len(data) != length:
                raise CryptoError("Insufficient pad data at offset")
            return data

    def remaining_bytes(self) -> int:
        try:
            size = os.path.getsize(self.pad_path)
            used = self._get_offset()
            return max(0, size - used)
        except Exception as e:
            logger.warning(f"Error calculating remaining bytes: {e}")
            return 0

    def current_offset(self) -> int:
        return self._get_offset()

    def current_sequence(self) -> int:
        return self._get_sequence()


class SecureFileTransfer:
    def __init__(self, message_protocol, pad_manager):
        self.message_protocol = message_protocol
        self.pad_manager = pad_manager
        self.chunk_size = 32 * 1024
        self.max_file_size = 50 * 1024 * 1024

    def send_file(self):
        if not self.connected:
            messagebox.showerror("Error", "Not connected!")
            return

        filepath = filedialog.askopenfilename(
            title="Select file to send",
            filetypes=[("All files", "*.*")]
        )

        if filepath:
            self.send_file_internal(filepath)  # Ugyanaz mint send_image!

        # Send chunks
        with open(filepath, 'rb') as f:
            chunk_num = 0
            bytes_sent = 0

            while bytes_sent < file_size:
                chunk_data = f.read(self.chunk_size)
                if not chunk_data:
                    break

                compressed = zlib.compress(chunk_data)

                chunk_msg = {
                    "type": "FILE_CHUNK",
                    "chunk_num": chunk_num,
                    "data": base64.b64encode(compressed).decode('ascii')
                }

                self._send_control_message(chunk_msg)
                bytes_sent += len(chunk_data)
                chunk_num += 1

                if progress_callback:
                    progress_callback(bytes_sent, file_size)

        # End marker
        self._send_control_message({"type": "FILE_END", "filename": filename})
        return True

    def _send_control_message(self, data: dict):
        import json
        control_msg = f"__FILE_TRANSFER__{json.dumps(data)}"
        return control_msg


class FileReceiver:
    def __init__(self, download_dir: str = "downloads"):
        try:
            self.download_dir = Path(download_dir)
            self.download_dir.mkdir(exist_ok=True)
            self.active_transfers = {}
            print(f"[DEBUG] FileReceiver initialized with download_dir: {self.download_dir}")
        except Exception as e:
            print(f"[ERROR] FileReceiver init failed: {e}")
            # Fallback
            self.download_dir = Path("downloads")
            self.download_dir.mkdir(exist_ok=True)
            self.active_transfers = {}
    def handle_file_message(self, control_data: dict, app_instance):
        msg_type = control_data.get("type")

        print(f"[DEBUG] Handling file message type: {msg_type}")  # Debug információ

        if msg_type == "FILE_START":
            return self._handle_file_start(control_data, app_instance)
        elif msg_type == "FILE_CHUNK":
            return self._handle_file_chunk(control_data, app_instance)
        elif msg_type == "FILE_END":
            return self._handle_file_end(control_data, app_instance)

        return False

    def _handle_file_start(self, data: dict, app):
        filename = data["filename"]
        file_size = data["size"]

        result = messagebox.askyesno(
            "Incoming File",
            f"Receive file: {filename}\nSize: {file_size // 1024}KB\n\nAccept?"
        )

        if not result:
            return False

        filepath = self.download_dir / filename
        counter = 1
        while filepath.exists():
            name, ext = os.path.splitext(filename)
            filepath = self.download_dir / f"{name}_{counter}{ext}"
            counter += 1

        print(f"[DEBUG] Creating file: {filepath}")  # Debug

        self.active_transfers[filename] = {
            "filepath": filepath,
            "file_handle": open(filepath, "wb"),
            "expected_size": file_size,
            "received_size": 0,
            "chunks_received": 0  # Chunk számláló hozzáadása
        }

        app.log(f"Starting file receive: {filename}", "SUCCESS")
        return True

    def _handle_file_chunk(self, data: dict, app):
        if not self.active_transfers:
            print("[DEBUG] No active transfers")
            return False

        filename = list(self.active_transfers.keys())[0]
        transfer = self.active_transfers[filename]

        try:
            compressed_data = base64.b64decode(data["data"])
            chunk_data = zlib.decompress(compressed_data)

            print(f"[DEBUG] Writing chunk {data.get('chunk_num', '?')} ({len(chunk_data)} bytes)")

            transfer["file_handle"].write(chunk_data)
            transfer["file_handle"].flush()  # KRITIKUS: flush a fájlt
            transfer["received_size"] += len(chunk_data)
            transfer["chunks_received"] += 1

            progress = (transfer["received_size"] / transfer["expected_size"]) * 100
            app.file_progress['value'] = progress
            app.file_status_label.config(text=f"Receiving: {progress:.1f}%")

            print(f"[DEBUG] Progress: {progress:.1f}% ({transfer['received_size']}/{transfer['expected_size']})")

            return True
        except Exception as e:
            app.log(f"Chunk error: {e}", "ERROR")
            print(f"[DEBUG] Chunk error: {e}")
            return False

    def _handle_file_end(self, data: dict, app):
        filename = data["filename"]
        print(f"[DEBUG] File end for: {filename}")

        if filename in self.active_transfers:
            transfer = self.active_transfers[filename]
            transfer["file_handle"].close()  # KRITIKUS: fájl bezárása

            print(f"[DEBUG] File saved: {transfer['filepath']}")
            print(f"[DEBUG] Final size: {transfer['received_size']} bytes, chunks: {transfer['chunks_received']}")

            app.log(f"File received: {transfer['filepath'].name}", "SUCCESS")
            messagebox.showinfo("Transfer Complete", f"File saved: {transfer['filepath']}")

            del self.active_transfers[filename]

            # Progress reset
            app.file_progress['value'] = 0
            app.file_status_label.config(text="Ready")

        return True
class SecureTLSManager:
    @staticmethod
    def create_secure_context(is_server: bool = False) -> ssl.SSLContext:
        """Create hardened TLS context"""
        if is_server:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(TLS_SERVER_CERT_FILE, TLS_SERVER_KEY_FILE)
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_cert_chain(TLS_CLIENT_CERT_FILE, TLS_CLIENT_KEY_FILE)

        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False
        context.load_verify_locations(TLS_CA_CERT_FILE)

        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS:!3DES:!RC4')
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        context.options |= ssl.OP_NO_COMPRESSION
        context.options |= ssl.OP_NO_RENEGOTIATION
        context.options |= ssl.OP_SINGLE_DH_USE
        context.options |= ssl.OP_SINGLE_ECDH_USE

        return context

    @staticmethod
    def get_cert_fingerprint(cert_der_bytes: bytes) -> str:
        return hashlib.sha3_256(cert_der_bytes).hexdigest()

    @staticmethod
    def save_trusted_certificate(host: str, port: int, cert_der_bytes: bytes):
        os.makedirs(TLS_TRUSTED_CERTS_DIR, exist_ok=True)

        try:
            os.chmod(TLS_TRUSTED_CERTS_DIR, 0o700)
        except OSError:
            pass

        fingerprint = SecureTLSManager.get_cert_fingerprint(cert_der_bytes)
        timestamp = datetime.datetime.utcnow().isoformat() + 'Z'

        cert_store_path = os.path.join(TLS_TRUSTED_CERTS_DIR, TLS_CERT_STORE)

        trusted_certs = {}
        if os.path.exists(cert_store_path):
            try:
                with open(cert_store_path, 'r') as f:
                    trusted_certs = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Could not load certificate store: {e}")

        host_key = f"{host}:{port}"
        trusted_certs[host_key] = {
            'fingerprint': fingerprint,
            'timestamp': timestamp,
            'cert_der': base64.b64encode(cert_der_bytes).decode('ascii')
        }

        temp_path = cert_store_path + '.tmp'
        with open(temp_path, 'w') as f:
            json.dump(trusted_certs, f, indent=2)
            f.flush()
            safe_fsync(f)

        try:
            os.chmod(temp_path, 0o600)
        except OSError:
            pass

        if os.path.exists(cert_store_path):
            os.remove(cert_store_path)
        os.rename(temp_path, cert_store_path)

    @staticmethod
    def verify_certificate_trust(host: str, port: int, cert_der_bytes: bytes) -> Tuple[bool, str]:
        fingerprint = SecureTLSManager.get_cert_fingerprint(cert_der_bytes)
        cert_store_path = os.path.join(TLS_TRUSTED_CERTS_DIR, TLS_CERT_STORE)

        if os.path.exists(cert_store_path):
            try:
                with open(cert_store_path, 'r') as f:
                    trusted_certs = json.load(f)

                host_key = f"{host}:{port}"
                if host_key in trusted_certs:
                    stored_fp = trusted_certs[host_key]['fingerprint']
                    if constant_time.bytes_eq(stored_fp.encode(), fingerprint.encode()):
                        return True, "Certificate matches stored fingerprint"
                    else:
                        return False, f"SECURITY ALERT: Certificate fingerprint mismatch!"

            except (json.JSONDecodeError, OSError, KeyError) as e:
                logger.warning(f"Certificate store error: {e}")

        SecureTLSManager.save_trusted_certificate(host, port, cert_der_bytes)
        return True, "Certificate automatically trusted and saved"


class KeyExchangeProtocol:
    def __init__(self, connection, ed25519_private, peer_ed25519_pub_pem, dilithium_private, peer_dilithium_pub):
        self.connection = connection
        self.ed25519_private = ed25519_private
        self.peer_ed25519_pub_pem = peer_ed25519_pub_pem
        self.dilithium_private = dilithium_private
        self.peer_dilithium_pub = peer_dilithium_pub

    def perform_key_exchange(self, connection, is_server: bool, peer_public_key: bytes,
                             peer_dilithium_pub: bytes) -> bytes:
        """Enhanced key exchange with hybrid Ed25519 + Dilithium signatures"""
        try:
            original_timeout = connection.gettimeout()
            connection.settimeout(30.0)

            logger.info("Starting ECDHE key generation...")
            ecdhe_private = ec.generate_private_key(ec.SECP384R1())
            ecdhe_public = ecdhe_private.public_key()

            ecdhe_public_bytes = ecdhe_public.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )

            logger.info(f"Sending ECDHE public key ({len(ecdhe_public_bytes)} bytes)")
            connection.sendall(struct.pack("!H", len(ecdhe_public_bytes)) + ecdhe_public_bytes)

            logger.info("Waiting for peer ECDHE public key...")
            peer_ecdhe_len_data = self._recv_exact(connection, 2)
            peer_ecdhe_len = struct.unpack("!H", peer_ecdhe_len_data)[0]

            if peer_ecdhe_len > 200 or peer_ecdhe_len < 50:
                raise ProtocolError(f"Invalid ECDHE key length: {peer_ecdhe_len}")

            peer_ecdhe_bytes = self._recv_exact(connection, peer_ecdhe_len)
            logger.info(f"Received peer ECDHE key ({len(peer_ecdhe_bytes)} bytes)")

            try:
                peer_ecdhe_public = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP384R1(), peer_ecdhe_bytes
                )
            except ValueError as e:
                raise CryptoError(f"Invalid peer ECDHE key: {e}")

            ecdhe_shared = ecdhe_private.exchange(ec.ECDH(), peer_ecdhe_public)
            logger.info("ECDHE shared secret computed")

            if is_server:
                header = self._recv_exact(connection, 2)
                nlen = struct.unpack("!H", header)[0]
                client_nonce = self._recv_exact(connection, nlen)
                logger.info(f"[KEX][SERVER] Received client nonce ({len(client_nonce)} bytes)")

                server_pk, server_sk = kyber512.keypair()
                sig_input = server_pk + client_nonce

                # HYBRID SIGNATURE: Ed25519 + Dilithium
                ed25519_signature = self.ed25519_private.sign(sig_input)
                dilithium_signature = dilithium2.sign(sig_input, self.dilithium_private)

                logger.info(
                    f"[KEX][SERVER] Generated hybrid signatures - Ed25519: {len(ed25519_signature)} bytes, Dilithium: {len(dilithium_signature)} bytes")

                blob = (struct.pack("!H", len(server_pk)) + server_pk +
                        struct.pack("!H", len(ed25519_signature)) + ed25519_signature +
                        struct.pack("!H", len(dilithium_signature)) + dilithium_signature)

                connection.sendall(struct.pack("!I", len(blob)) + blob)
                logger.info(f"[KEX][SERVER] Sent Kyber PK with hybrid signatures (total: {len(blob)} bytes)")

                header = self._recv_exact(connection, 2)
                L_ct = struct.unpack("!H", header)[0]
                ct = self._recv_exact(connection, L_ct)
                logger.info(f"[KEX][SERVER] Received ciphertext len={len(ct)}")

                shared_secret = kyber512.decap(ct, server_sk)

            else:  # client
                client_nonce = os.urandom(32)
                connection.sendall(struct.pack("!H", len(client_nonce)) + client_nonce)
                logger.info(f"[KEX][CLIENT] Sent client nonce ({len(client_nonce)} bytes)")

                L_blob = struct.unpack("!I", self._recv_exact(connection, 4))[0]
                blob = self._recv_exact(connection, L_blob)

                pos = 0
                pk_len = struct.unpack("!H", blob[pos:pos + 2])[0]
                pos += 2
                server_pk = blob[pos:pos + pk_len]
                pos += pk_len

                ed25519_sig_len = struct.unpack("!H", blob[pos:pos + 2])[0]
                pos += 2
                ed25519_signature = blob[pos:pos + ed25519_sig_len]
                pos += ed25519_sig_len

                dilithium_sig_len = struct.unpack("!H", blob[pos:pos + 2])[0]
                pos += 2
                dilithium_signature = blob[pos:pos + dilithium_sig_len]

                logger.info(
                    f"[KEX][CLIENT] Received hybrid signatures - Ed25519: {len(ed25519_signature)} bytes, Dilithium: {len(dilithium_signature)} bytes")

                # HYBRID SIGNATURE VERIFICATION
                try:
                    peer_ed25519_obj = serialization.load_pem_public_key(self.peer_ed25519_pub_pem)
                    peer_ed25519_obj.verify(ed25519_signature, server_pk + client_nonce)
                    logger.info("[KEX][CLIENT] Ed25519 signature verification successful")
                except Exception as ex:
                    raise CryptoError(f"Ed25519 signature verification failed: {ex}")

                try:
                    dilithium2.verify(dilithium_signature, server_pk + client_nonce, self.peer_dilithium_pub)
                    logger.info("[KEX][CLIENT] Dilithium signature verification successful")
                except Exception as ex:
                    raise CryptoError(f"Dilithium signature verification failed: {ex}")

                logger.info("[KEX][CLIENT] Hybrid signature verification successful")

                enc_res = kyber512.encap(server_pk)
                if isinstance(enc_res, tuple) and len(enc_res) == 2:
                    a, b = enc_res
                    if isinstance(a, (bytes, bytearray)) and len(a) == 32:
                        shared_secret = a
                        ct = b
                    elif isinstance(b, (bytes, bytearray)) and len(b) == 32:
                        shared_secret = b
                        ct = a
                    else:
                        ct, shared_secret = enc_res
                else:
                    raise ValueError("Unexpected Kyber encap result")

                connection.sendall(struct.pack("!H", len(ct)) + ct)
                logger.info(f"[KEX][CLIENT] Sent ciphertext len={len(ct)}")

            # Salt exchange for key derivation
            salt = secrets.token_bytes(32)
            if is_server:
                logger.info("Server: Exchanging salts...")
                connection.sendall(salt)
                peer_salt = self._recv_exact(connection, 32)
                combined_salt = salt + peer_salt
            else:
                logger.info("Client: Exchanging salts...")
                peer_salt = self._recv_exact(connection, 32)
                connection.sendall(salt)
                combined_salt = peer_salt + salt

            logger.info(f"Combined salt: {combined_salt.hex()[:32]}...")

            # Derive session keys
            combined_secret = ecdhe_shared + shared_secret
            context_info = b"SecureChat-v2.0-HybridSig-" + (
                b"agsjfbvjdbfjskfuvbsksocusblrlhvbdsjcbsnfmskcosldmfbsisldf...wbfoa")

            logger.info(f"[DEBUG] Kyber shared secret ({len(shared_secret)} bytes): {shared_secret.hex()[:64]}...")
            logger.info(f"Context info: {context_info}")

            master_key = HKDF(
                algorithm=hashes.SHA3_256(),
                length=96,
                salt=combined_salt,
                info=context_info
            ).derive(combined_secret)

            aes_key = master_key[:32]
            hmac_key = master_key[32:64]
            auth_key = master_key[64:96]

            logger.info(f"[DEBUG] Combined secret ({len(combined_secret)} bytes): {combined_secret.hex()[:64]}...")

            self.session_keys = {
                'aes': aes_key,
                'hmac': hmac_key,
                'auth': auth_key
            }

            self.exchange_complete = True
            logger.info("Hybrid signature key exchange completed successfully")

            connection.settimeout(original_timeout)
            return aes_key

        except Exception as e:
            logger.error(f"Hybrid key exchange failed: {e}")
            self.session_keys = None
            try:
                connection.settimeout(original_timeout)
            except:
                pass
            raise

    def _recv_exact(self, connection, n: int) -> bytes:
        """Receive exact number of bytes with improved timeout handling"""
        buf = b""
        deadline = time.time() + CONNECTION_TIMEOUT

        while len(buf) < n:
            if time.time() > deadline:
                raise TimeoutError(f"Connection timeout during receive (got {len(buf)}/{n} bytes)")

            try:
                remaining = n - len(buf)
                chunk = connection.recv(min(remaining, 8192))
                if not chunk:
                    raise ConnectionError(f"Connection closed unexpectedly (got {len(buf)}/{n} bytes)")
                buf += chunk
                logger.debug(f"Received {len(chunk)} bytes, total: {len(buf)}/{n}")
            except socket.timeout:
                logger.debug("Socket timeout, retrying...")
                continue
            except Exception as e:
                logger.error(f"Error during receive: {e}")
                raise

        return buf

    def get_session_key(self, key_type: str) -> bytes:
        if not self.exchange_complete or not self.session_keys or key_type not in self.session_keys:
            raise CryptoError(f"Session key '{key_type}' not available")
        return self.session_keys[key_type]

    def destroy_keys(self):
        """Securely destroy session keys"""
        if self.session_keys:
            for key in self.session_keys.values():
                if isinstance(key, bytes):
                    key = bytearray(key)
                    for i in range(len(key)):
                        key[i] = 0
            self.session_keys = None
        self.exchange_complete = False


class SecureMessageProtocol:
    def __init__(self, aes_key: bytes, hmac_key: bytes, auth_key: bytes, pad_manager: SecurePadManager):
        self.aes_key = aes_key
        self.hmac_key = hmac_key
        self.auth_key = auth_key
        self.pad_manager = pad_manager
        self.replay_protection = ReplayProtection()
        self.rate_limiter = RateLimiter()
        self.message_counter = 0
        self.lock = threading.RLock()

    def encrypt_message(self, plaintext: str) -> bytes:
        if not self.rate_limiter.allow_request():
            print("provb")

        message_bytes = plaintext.encode('utf-8')
        if len(message_bytes) == 0 or len(message_bytes) > MAX_MESSAGE_SIZE:
            raise ValueError("Invalid message size")

        with self.lock:
            self.message_counter += 1
            if self.message_counter > 0xFFFFFFFF:
                raise CryptoError("Message counter overflow")

        try:
            offset, sequence, pad_data = self.pad_manager.prepare_send(len(message_bytes))

            otp_encrypted = bytes(a ^ b for a, b in zip(message_bytes, pad_data))

            nonce = secrets.token_bytes(16)
            timestamp = struct.pack("!Q", int(time.time() * 1000))

            payload = (struct.pack("!Q", offset) +
                       struct.pack("!I", sequence) +
                       struct.pack("!I", self.message_counter) +
                       timestamp + nonce + otp_encrypted)

            aesgcm = AESGCM(self.aes_key)
            aes_nonce = secrets.token_bytes(12)
            ciphertext = aesgcm.encrypt(aes_nonce, payload, None)

            auth_data = aes_nonce + ciphertext
            hmac_obj = hmac.new(self.hmac_key, auth_data, hashlib.sha3_256)
            auth_tag = hmac_obj.digest()

            final_auth = hmac.new(self.auth_key, auth_data + auth_tag, hashlib.sha3_256)
            final_tag = final_auth.digest()[:16]

            self.pad_manager.confirm_send(len(message_bytes), offset, sequence)

            final_packet = (struct.pack("!H", len(aes_nonce)) + aes_nonce +
                            struct.pack("!I", len(ciphertext)) + ciphertext +
                            auth_tag + final_tag)
            combined1, pad1 = encrypt_next_key(final_packet)  # csak a ciphertext kell a következő réteghez
            combined2, pad2 = encrypt_next_key_cha(combined1)
            combined3, pad3 = encrypt_next_key_Serpent(combined2)

            logger.debug(f"hi: {combined3}")
            return combined3

        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    def decrypt_message(self, packet: bytes) -> str:
        if len(packet) < 70:
            raise ProtocolError("Packet too short")
        logger.debug(packet)

        plaintext_step2 = decrypt_combined_next_key_Serpent(packet)
        plaintext_step3 = decrypt_combined_next_key_cha(plaintext_step2)
        plaintext_final1 = decrypt_combined_next_key(plaintext_step3)
        packet=plaintext_final1
        logger.debug(packet)

        try:
            pos = 0

            nonce_len = struct.unpack("!H", packet[pos:pos + 2])[0]
            pos += 2

            if nonce_len != 12:
                raise ProtocolError("Invalid AES nonce length")

            aes_nonce = packet[pos:pos + nonce_len]
            pos += nonce_len

            ct_len = struct.unpack("!I", packet[pos:pos + 4])[0]
            pos += 4

            ciphertext = packet[pos:pos + ct_len]
            pos += ct_len

            if len(packet) < pos + 48:
                raise ProtocolError("Insufficient data for authentication")

            received_hmac = packet[pos:pos + 32]
            pos += 32

            received_final = packet[pos:pos + 16]
            pos += 16

            if pos != len(packet):
                raise ProtocolError("Packet length mismatch")

            auth_data = aes_nonce + ciphertext
            expected_hmac = hmac.new(self.hmac_key, auth_data, hashlib.sha3_256).digest()

            if not constant_time.bytes_eq(expected_hmac, received_hmac):
                raise CryptoError("HMAC verification failed")

            expected_final = hmac.new(self.auth_key, auth_data + received_hmac, hashlib.sha3_256).digest()[:16]
            if not constant_time.bytes_eq(expected_final, received_final):
                raise CryptoError("Final authentication failed")

            aesgcm = AESGCM(self.aes_key)
            payload = aesgcm.decrypt(aes_nonce, ciphertext, None)

            if len(payload) < 1:
                raise ProtocolError("Invalid payload length")

            pos = 0
            offset = struct.unpack("!Q", payload[pos:pos + 8])[0]
            pos += 8

            sequence = struct.unpack("!I", payload[pos:pos + 4])[0]
            pos += 4

            msg_counter = struct.unpack("!I", payload[pos:pos + 4])[0]
            pos += 4

            timestamp = struct.unpack("!Q", payload[pos:pos + 8])[0]
            pos += 8

            msg_nonce = payload[pos:pos + 16]
            pos += 16

            otp_encrypted = payload[pos:]

            current_time = int(time.time() * 1000)
            if abs(current_time - timestamp) > 300000:
                raise ProtocolError("Message timestamp too old/future")

            self.replay_protection.validate_message(msg_nonce, sequence)

            pad_data = self.pad_manager.read_pad_data(offset, len(otp_encrypted))
            plaintext_bytes = bytes(a ^ b for a, b in zip(otp_encrypted, pad_data))

            try:
                plaintext = plaintext_bytes.decode('utf-8')

                # File transfer message handling - JAVÍTOTT VERZIÓ
                if plaintext.startswith("__FILE_TRANSFER__"):
                    import json
                    try:
                        control_data = json.loads(plaintext[17:])
                        # Itt volt a hiba - az app_instance referenciát át kell adni
                        if hasattr(self, 'app_instance') and self.app_instance and hasattr(self.app_instance,
                                                                                           'file_receiver'):
                            success = self.app_instance.file_receiver.handle_file_message(control_data,
                                                                                          self.app_instance)
                            if success:
                                return f"[FILE] {control_data.get('type', 'Unknown')} - processed"
                            else:
                                return f"[FILE] {control_data.get('type', 'Unknown')} - failed"
                        else:
                            return f"[FILE] {control_data.get('type', 'Unknown')} - no receiver"
                    except json.JSONDecodeError:
                        # If JSON parsing fails, treat as regular message
                        pass

                return plaintext

            except UnicodeDecodeError:
                raise ProtocolError("Invalid UTF-8 in decrypted message")

        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    def destroy_keys(self):
        """Securely destroy encryption keys"""
        for key_name in ['aes_key', 'hmac_key', 'auth_key']:
            key = getattr(self, key_name, None)
            if key and isinstance(key, bytes):
                key_array = bytearray(key)
                for i in range(len(key_array)):
                    key_array[i] = 0
                setattr(self, key_name, None)


def ensure_tls_certs():
    """Generate TLS certificates with enhanced security"""
    if not all(os.path.exists(f) for f in [TLS_CA_CERT_FILE, TLS_CA_KEY_FILE]):
        generate_ca_certificate()

    if not all(os.path.exists(f) for f in [TLS_SERVER_CERT_FILE, TLS_SERVER_KEY_FILE]):
        generate_signed_cert(is_server=True)

    if not all(os.path.exists(f) for f in [TLS_CLIENT_CERT_FILE, TLS_CLIENT_KEY_FILE]):
        generate_signed_cert(is_server=False)


def generate_ca_certificate():
    """Generate CA certificate with enhanced security parameters"""
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    ca_subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Unknown"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Unknown"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat-CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat-Root-CA"),
    ])

    ca_cert = x509.CertificateBuilder().subject_name(
        ca_subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1825)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(ca_private_key, hashes.SHA3_256())

    SecureAtomicOperations.atomic_write(TLS_CA_CERT_FILE, ca_cert.public_bytes(serialization.Encoding.PEM))
    SecureAtomicOperations.atomic_write(TLS_CA_KEY_FILE, ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

    try:
        os.chmod(TLS_CA_KEY_FILE, 0o600)
        os.chmod(TLS_CA_CERT_FILE, 0o644)
    except OSError:
        pass


def generate_signed_cert(is_server: bool = True):
    """Generate signed certificate with enhanced security"""
    import ipaddress

    with open(TLS_CA_CERT_FILE, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(TLS_CA_KEY_FILE, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)

    if is_server:
        common_name = "SecureChat-Server"
        cert_file = TLS_SERVER_CERT_FILE
        key_file = TLS_SERVER_KEY_FILE
    else:
        common_name = "SecureChat-Client"
        cert_file = TLS_CLIENT_CERT_FILE
        key_file = TLS_CLIENT_KEY_FILE

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Unknown"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Unknown"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    san_list = [
        x509.DNSName("localhost"),
        x509.DNSName("127.0.0.1"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("::1")),
    ]

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=90)
    ).add_extension(
        x509.SubjectAlternativeName(san_list),
        critical=False,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=True,
    ).sign(ca_private_key, hashes.SHA3_256())

    SecureAtomicOperations.atomic_write(cert_file, cert.public_bytes(serialization.Encoding.PEM))
    SecureAtomicOperations.atomic_write(key_file, private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

    try:
        os.chmod(key_file, 0o600)
        os.chmod(cert_file, 0o644)
    except OSError:
        pass


def ensure_keys_exist():
    """Generate Ed25519 and Dilithium keys with proper security"""
    # Ed25519 keys
    if not all(os.path.exists(f) for f in [MY_PRIV_FILE, MY_PUB_FILE]):
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()

        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        SecureAtomicOperations.atomic_write(MY_PRIV_FILE, priv_pem)
        SecureAtomicOperations.atomic_write(MY_PUB_FILE, pub_pem)

        try:
            os.chmod(MY_PRIV_FILE, 0o600)
            os.chmod(MY_PUB_FILE, 0o644)
        except OSError:
            pass

    # Dilithium keys
    if not all(os.path.exists(f) for f in [MY_DILITHIUM_PRIV_FILE, MY_DILITHIUM_PUB_FILE]):
        dilithium_pub, dilithium_priv = dilithium2.keypair()

        SecureAtomicOperations.atomic_write(MY_DILITHIUM_PRIV_FILE, dilithium_priv)
        SecureAtomicOperations.atomic_write(MY_DILITHIUM_PUB_FILE, dilithium_pub)

        try:
            os.chmod(MY_DILITHIUM_PRIV_FILE, 0o600)
            os.chmod(MY_DILITHIUM_PUB_FILE, 0o644)
        except OSError:
            pass


def secure_pad_generator(filepath: str, size_bytes: int, progress_callback=None):
    """Generate cryptographically secure one-time pad"""
    chunk_size = min(PAD_CHUNK, size_bytes)
    written = 0

    temp_file = filepath + '.generating'

    try:
        with open(temp_file, 'wb') as f:
            while written < size_bytes:
                remaining = size_bytes - written
                current_chunk_size = min(chunk_size, remaining)

                chunk = secrets.token_bytes(current_chunk_size)
                f.write(chunk)
                f.flush()

                written += current_chunk_size

                if progress_callback:
                    progress_callback(written, size_bytes)

                if written % (10 * PAD_CHUNK) == 0:
                    safe_fsync(f)

        safe_fsync(f)

        try:
            os.chmod(temp_file, 0o600)
        except OSError:
            pass

        if os.path.exists(filepath):
            os.remove(filepath)
        os.rename(temp_file, filepath)

    except Exception as e:
        if os.path.exists(temp_file):
            SecureAtomicOperations.secure_delete(temp_file)
        raise


class ConnectionManager:
    def __init__(self):
        self.connections = {}
        self.connection_counts = {}
        self.lock = threading.RLock()

    def can_accept_connection(self, addr: str) -> bool:
        with self.lock:
            count = self.connection_counts.get(addr, 0)
            return count < MAX_CONNECTIONS_PER_IP

    def register_connection(self, addr: str, conn_id: str):
        with self.lock:
            self.connections[conn_id] = addr
            self.connection_counts[addr] = self.connection_counts.get(addr, 0) + 1

    def unregister_connection(self, conn_id: str):
        with self.lock:
            if conn_id in self.connections:
                addr = self.connections[conn_id]
                del self.connections[conn_id]

                if addr in self.connection_counts:
                    self.connection_counts[addr] -= 1
                    if self.connection_counts[addr] <= 0:
                        del self.connection_counts[addr]


class SecureChatApp:
    def __init__(self, root):
        self.root = root
        root.title("Secure Multi-Layer Chat Application v2.0 - Hybrid Signatures")
        root.geometry("1200x900")
        root.protocol("WM_DELETE_WINDOW", self.on_closing)

        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, self.signal_handler)

        ensure_tls_certs()
        ensure_keys_exist()

        try:
            # Load Ed25519 keys
            with open(MY_PRIV_FILE, "rb") as f:
                self.my_private_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(MY_PUB_FILE, "rb") as f:
                self.my_public_key = f.read()

            # Load Dilithium keys
            with open(MY_DILITHIUM_PRIV_FILE, "rb") as f:
                self.my_dilithium_private = f.read()
            with open(MY_DILITHIUM_PUB_FILE, "rb") as f:
                self.my_dilithium_public = f.read()

        except Exception as e:
            messagebox.showerror("Error", f"Could not load keys: {e}")
            sys.exit(1)

        self.pad_manager = None
        self.connection = None
        self.tls_connection = None
        self.message_protocol = None
        self.key_exchange = None
        self.connected = False
        self.is_server = False
        self.connection_manager = ConnectionManager()
        self.session_start_time = None

        self.setup_gui()
        self.load_pad_config()
        self.file_receiver = FileReceiver()
    def signal_handler(self, signum, frame):
        """Handle system signals gracefully"""
        logger.info(f"Received signal {signum}, shutting down...")
        self.cleanup_and_exit()

    def on_closing(self):
        """Handle window close event"""
        self.cleanup_and_exit()

    def cleanup_and_exit(self):
        """Clean shutdown with key destruction"""
        try:
            self.disconnect()

            if self.key_exchange:
                self.key_exchange.destroy_keys()

            if self.message_protocol:
                self.message_protocol.destroy_keys()

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
        finally:
            self.root.quit()
            sys.exit(0)

    def setup_gui(self):
        """Setup enhanced GUI with hybrid signature security indicators"""
        style = ttk.Style()
        style.theme_use('clam')

        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(8, weight=1)  # Módosítva 7-ről 8-ra

        conn_frame = ttk.LabelFrame(main_frame, text="Connection Settings", padding="10")
        conn_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        conn_frame.columnconfigure(1, weight=1)
        conn_frame.columnconfigure(3, weight=1)

        ttk.Label(conn_frame, text="Host:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.host_entry = ttk.Entry(conn_frame, width=15)
        self.host_entry.grid(row=0, column=1, sticky="ew", padx=(0, 20))
        self.host_entry.insert(0, "127.0.0.1")

        ttk.Label(conn_frame, text="Port:").grid(row=0, column=2, sticky="w", padx=(0, 5))
        self.port_entry = ttk.Entry(conn_frame, width=8)
        self.port_entry.grid(row=0, column=3, sticky="ew", padx=(0, 20))
        self.port_entry.insert(0, "9000")

        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self.connect)
        self.connect_btn.grid(row=0, column=4, padx=(10, 0))

        self.status_label = ttk.Label(main_frame, text="Status: Disconnected",
                                      font=("", 10, "bold"), foreground="red")
        self.status_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 10))

        security_frame = ttk.LabelFrame(main_frame, text="Hybrid Security Layers", padding="10")
        security_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        security_frame.columnconfigure(0, weight=1)

        self.security_labels = {}
        layers = [
            ("TLS 1.3", "Transport Layer Security"),
            ("Ed25519", "Classical Digital Signatures"),
            ("Dilithium2", "Post-Quantum Signatures"),
            ("ECDHE", "Elliptic Curve Key Exchange"),
            ("Kyber512", "Post-Quantum Key Encapsulation"),
            ("AES-GCM", "Authenticated Encryption"),
            ("HMAC-SHA3", "Message Authentication"),
            ("OTP", "One-Time Pad Encryption"),
            ("Anti-Replay", "Replay Attack Protection")
        ]

        for i, (layer, desc) in enumerate(layers):
            row = i // 5
            col = i % 5

            frame = ttk.Frame(security_frame)
            frame.grid(row=row, column=col, padx=3, pady=2, sticky="w")

            label = ttk.Label(frame, text=f"✗ {layer}", font=("", 9))
            label.pack()

            self.security_labels[layer] = label

        session_frame = ttk.LabelFrame(main_frame, text="Session Information", padding="5")
        session_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, 10))

        self.session_info = ttk.Label(session_frame, text="No active session", font=("", 9))
        self.session_info.grid(row=0, column=0, sticky="w")

        cert_frame = ttk.LabelFrame(main_frame, text="Certificate & Key Management", padding="5")
        cert_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(0, 10))

        ttk.Button(cert_frame, text="View Trusted Certs",
                   command=self.show_trusted_certs).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(cert_frame, text="Clear Cert Store",
                   command=self.clear_cert_store).grid(row=0, column=1, padx=(0, 10))
        ttk.Button(cert_frame, text="Hybrid Key Fingerprints",
                   command=self.show_key_fingerprints).grid(row=0, column=2, padx=(0, 10))
        ttk.Button(cert_frame, text="Security Audit",
                   command=self.security_audit).grid(row=0, column=3)

        msg_frame = ttk.LabelFrame(main_frame, text="Send Message", padding="10")
        msg_frame.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        msg_frame.columnconfigure(1, weight=1)

        self.send_btn = ttk.Button(msg_frame, text="Send", command=self.send_message, state="disabled")
        self.send_btn.grid(row=0, column=0, padx=(0, 10))

        self.message_entry = ttk.Entry(msg_frame, font=("", 11))
        self.message_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        self.message_entry.bind("<Return>", lambda e: self.send_message())

        self.char_count = ttk.Label(msg_frame, text="0/1000", font=("", 9))
        self.char_count.grid(row=0, column=2)
        self.message_entry.bind("<KeyRelease>", self.update_char_count)

        # KOMPAKT FILE TRANSFER SZEKCIÓ
        file_frame = ttk.LabelFrame(main_frame, text="File Transfer", padding="5")
        file_frame.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(0, 5))
        file_frame.columnconfigure(2, weight=1)

        # Gombok egy sorban, kompaktan
        ttk.Button(file_frame, text="Send File", command=self.send_file).grid(row=0, column=0, padx=(0, 5))
        ttk.Button(file_frame, text="Send Image", command=self.send_image).grid(row=0, column=1, padx=(0, 10))

        # Progress bar és status ugyanabban a sorban
        self.file_progress = ttk.Progressbar(file_frame, orient="horizontal", mode="determinate", length=200)
        self.file_progress.grid(row=0, column=2, sticky="ew", padx=(0, 10))

        self.file_status_label = ttk.Label(file_frame, text="Ready", font=("", 9))
        self.file_status_label.grid(row=0, column=3, sticky="w")

        # ONE-TIME PAD MANAGEMENT
        pad_frame = ttk.LabelFrame(main_frame, text="One-Time Pad Management", padding="10")
        pad_frame.grid(row=7, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        pad_frame.columnconfigure(1, weight=1)

        ttk.Button(pad_frame, text="Generate Pad", command=self.generate_pad).grid(row=0, column=0, padx=(0, 10))

        self.pad_path_var = tk.StringVar(value="secure_pad.bin")
        pad_entry = ttk.Entry(pad_frame, textvariable=self.pad_path_var, font=("", 9))
        pad_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10))

        ttk.Button(pad_frame, text="Browse", command=self.browse_pad).grid(row=0, column=2, padx=(0, 10))
        ttk.Button(pad_frame, text="Verify Pad", command=self.verify_pad).grid(row=0, column=3)

        self.pad_progress = ttk.Progressbar(pad_frame, orient="horizontal", mode="determinate")
        self.pad_progress.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(10, 5))

        self.pad_info_label = ttk.Label(pad_frame, text="No pad loaded", font=("", 9))
        self.pad_info_label.grid(row=2, column=0, columnspan=4, sticky="w")

        # CHAT SZEKCIÓ
        chat_frame = ttk.LabelFrame(main_frame, text="Secure Chat Messages", padding="5")
        chat_frame.grid(row=8, column=0, columnspan=2, sticky="nsew")  # row 8-ra módosítva
        chat_frame.columnconfigure(0, weight=1)
        chat_frame.rowconfigure(0, weight=1)

        self.chat_text = scrolledtext.ScrolledText(
            chat_frame,
            width=100,
            height=25,
            font=("Consolas", 10),
            wrap=tk.WORD
        )
        self.chat_text.grid(row=0, column=0, sticky="nsew")
        self.chat_text.config(state="disabled")
    def update_char_count(self, event=None):
        """Update character count display"""
        text = self.message_entry.get()
        count = len(text.encode('utf-8'))
        self.char_count.config(text=f"{count}/{MAX_MESSAGE_SIZE}")

        if count > MAX_MESSAGE_SIZE:
            self.char_count.config(foreground="red")
        else:
            self.char_count.config(foreground="black")

    def log(self, message: str, level: str = "INFO"):
        """Enhanced logging with timestamps and levels"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        formatted_message = f"[{timestamp}] [{level}] {message}"

        logger.info(formatted_message)

        try:
            self.chat_text.config(state="normal")

            if level == "ERROR":
                self.chat_text.insert("end", formatted_message + "\n", "error")
                self.chat_text.tag_config("error", foreground="red")
            elif level == "SECURITY":
                self.chat_text.insert("end", formatted_message + "\n", "security")
                self.chat_text.tag_config("security", foreground="orange", font=("Consolas", 10, "bold"))
            elif level == "SUCCESS":
                self.chat_text.insert("end", formatted_message + "\n", "success")
                self.chat_text.tag_config("success", foreground="green")
            else:
                self.chat_text.insert("end", formatted_message + "\n")

            self.chat_text.config(state="disabled")
            self.chat_text.see("end")
            self.root.update_idletasks()
        except Exception:
            pass

    def update_security_layer(self, layer_name: str, active: bool):
        """Update security layer status indicators"""
        if layer_name in self.security_labels:
            symbol = "✓" if active else "✗"
            base_text = self.security_labels[layer_name].cget("text")[2:]
            self.security_labels[layer_name].config(text=f"{symbol} {base_text}")

            if active:
                self.security_labels[layer_name].config(foreground="green")
            else:
                self.security_labels[layer_name].config(foreground="red")

    def update_status(self, status: str):
        """Update connection status with color coding"""
        self.status_label.config(text=f"Status: {status}")

        if "SECURE" in status.upper() or "ESTABLISHED" in status.upper():
            self.status_label.config(foreground="green")
        elif "ERROR" in status.upper() or "FAILED" in status.upper():
            self.status_label.config(foreground="red")
        else:
            self.status_label.config(foreground="orange")

        self.log(f"Status: {status}")

    def update_session_info(self):
        """Update session information display"""
        if not self.connected or not self.session_start_time:
            self.session_info.config(text="No active session")
            return

        duration = int(time.time() - self.session_start_time)
        hours, remainder = divmod(duration, 3600)
        minutes, seconds = divmod(remainder, 60)

        role = "Server" if self.is_server else "Client"
        info = f"Role: {role} | Duration: {hours:02d}:{minutes:02d}:{seconds:02d}"

        if self.pad_manager:
            remaining = self.pad_manager.remaining_bytes()
            info += f" | Pad: {remaining // 1024}KB remaining"

        self.session_info.config(text=info)
        self.root.after(1000, self.update_session_info)

    def load_pad_config(self):
        """Load pad configuration with security validation"""
        if os.path.exists(PAD_PATH_CFG):
            try:
                with open(PAD_PATH_CFG, 'r') as f:
                    pad_path = f.read().strip()

                if pad_path and os.path.exists(pad_path):
                    self.pad_manager = SecurePadManager(pad_path)
                    self.pad_path_var.set(pad_path)
                    self.update_pad_info()
                    self.log(f"Loaded pad: {Path(pad_path).name}", "SUCCESS")
                else:
                    self.log("Configured pad file not found", "ERROR")

            except Exception as e:
                self.log(f"Error loading pad config: {e}", "ERROR")

    def update_pad_info(self):
        """Update pad information with security status"""
        if not self.pad_manager:
            self.pad_info_label.config(text="No pad loaded - INSECURE", foreground="red")
            self.pad_progress['value'] = 0
            self.update_security_layer("OTP", False)
            return

        try:
            remaining = self.pad_manager.remaining_bytes()
            total_size = os.path.getsize(self.pad_manager.pad_path)
            used_bytes = total_size - remaining
            used_percent = (used_bytes / total_size * 100) if total_size > 0 else 0

            remaining_mb = remaining / (1024 * 1024)
            total_mb = total_size / (1024 * 1024)

            pad_name = Path(self.pad_manager.pad_path).name
            info_text = (f"Pad: {pad_name} | Remaining: {remaining_mb:.1f}MB/{total_mb:.1f}MB "
                         f"({100 - used_percent:.1f}%) | Offset: {self.pad_manager.current_offset()}")

            if remaining < 1024 * 1024:
                self.pad_info_label.config(text=info_text + " - LOW PAD!", foreground="red")
            elif remaining < 10 * 1024 * 1024:
                self.pad_info_label.config(text=info_text + " - Warning", foreground="orange")
            else:
                self.pad_info_label.config(text=info_text, foreground="green")

            self.pad_progress['maximum'] = total_size
            self.pad_progress['value'] = used_bytes

            self.update_security_layer("OTP", remaining > 64 * 1024)

        except Exception as e:
            self.log(f"Error updating pad info: {e}", "ERROR")

    def generate_pad(self):
        """Generate secure one-time pad with progress tracking"""
        path = filedialog.asksaveasfilename(
            defaultextension=".bin",
            title="Save Secure One-Time Pad",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
        )
        if not path:
            return

        size_mb = 100
        result = messagebox.askquestion(
            "Generate Secure Pad",
            f"Generate a {size_mb}MB cryptographically secure pad?\n\n"
            f"This uses hardware random number generation and may take several minutes.\n\n"
            f"The pad will provide perfect secrecy when used correctly."
        )

        if result != 'yes':
            return

        self.generate_btn_state = self.send_btn.cget('state')
        self.send_btn.config(state='disabled')

        threading.Thread(target=self._generate_pad_thread, args=(path, size_mb * 1024 * 1024), daemon=True).start()

    def _generate_pad_thread(self, path: str, size_bytes: int):
        """Thread for secure pad generation"""
        try:
            def progress_callback(written, total):
                progress = (written / total) * 100
                self.pad_progress['value'] = written
                self.root.update_idletasks()

            self.pad_progress['maximum'] = size_bytes
            self.log("Starting secure pad generation...", "INFO")

            secure_pad_generator(path, size_bytes, progress_callback)

            self.pad_manager = SecurePadManager(path)
            self.pad_path_var.set(path)

            SecureAtomicOperations.atomic_write(PAD_PATH_CFG, path.encode())

            self.update_pad_info()
            self.log(f"Generated secure pad: {Path(path).name} ({size_bytes // (1024 ** 2)} MB)", "SUCCESS")

        except Exception as e:
            self.log(f"Pad generation failed: {e}", "ERROR")
            messagebox.showerror("Error", f"Pad generation failed: {e}")
        finally:
            self.pad_progress['value'] = 0
            if hasattr(self, 'generate_btn_state'):
                self.send_btn.config(state=self.generate_btn_state)

    def browse_pad(self):
        """Browse and load existing pad with validation"""
        path = filedialog.askopenfilename(
            title="Select Secure One-Time Pad",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
        )
        if path:
            try:
                if os.path.getsize(path) < 1024 * 1024:
                    if not messagebox.askyesno("Small Pad Warning",
                                               "This pad is smaller than 1MB and may be quickly exhausted.\n\n"
                                               "Continue anyway?"):
                        return

                self.pad_manager = SecurePadManager(path)
                self.pad_path_var.set(path)

                SecureAtomicOperations.atomic_write(PAD_PATH_CFG, path.encode())
                self.update_pad_info()
                self.log(f"Loaded pad: {Path(path).name}", "SUCCESS")

            except Exception as e:
                self.log(f"Error loading pad: {e}", "ERROR")
                messagebox.showerror("Error", f"Could not load pad file:\n{e}")

    def verify_pad(self):
        """Verify pad integrity"""
        if not self.pad_manager:
            messagebox.showwarning("Warning", "No pad loaded to verify.")
            return

        try:
            self.pad_manager._verify_pad_integrity()
            messagebox.showinfo("Pad Verification", "Pad integrity verified successfully.")
            self.log("Pad integrity verification passed", "SUCCESS")
        except Exception as e:
            messagebox.showerror("Verification Failed", f"Pad integrity check failed:\n{e}")
            self.log(f"Pad verification failed: {e}", "SECURITY")

    def security_audit(self):
        """Display comprehensive security audit with hybrid signatures"""
        audit_window = tk.Toplevel(self.root)
        audit_window.title("Hybrid Security Audit Report")
        audit_window.geometry("700x600")
        audit_window.transient(self.root)

        text_widget = scrolledtext.ScrolledText(audit_window, font=("Consolas", 9), wrap=tk.WORD)
        text_widget.pack(fill="both", expand=True, padx=10, pady=10)

        audit_report = self._generate_security_audit()
        text_widget.insert("1.0", audit_report)
        text_widget.config(state="disabled")

    def _generate_security_audit(self) -> str:
        """Generate comprehensive security audit report with hybrid signatures"""
        report = "SECURE CHAT - HYBRID SIGNATURE SECURITY AUDIT\n"
        report += "=" * 60 + "\n\n"
        report += f"Generated: {datetime.datetime.utcnow().isoformat()}Z\n\n"

        report += "CRYPTOGRAPHIC COMPONENTS:\n"
        report += "-" * 30 + "\n"
        report += "* TLS 1.3 with mutual authentication\n"
        report += "* Ed25519 classical digital signatures\n"
        report += "* Dilithium2 post-quantum signatures\n"
        report += "* HYBRID SIGNATURE VERIFICATION\n"
        report += "* ECDHE P-384 for forward secrecy\n"
        report += "* Kyber512 post-quantum key encapsulation\n"
        report += "* AES-256-GCM authenticated encryption\n"
        report += "* HMAC-SHA3-256 message authentication\n"
        report += "* One-time pad for perfect secrecy\n"
        report += "* Anti-replay protection with nonce tracking\n\n"

        report += "SIGNATURE SECURITY:\n"
        report += "-" * 20 + "\n"
        report += "* Classical security: Ed25519 (256-bit)\n"
        report += "* Quantum-resistant: Dilithium2 (NIST Level 2)\n"
        report += "* Both signatures must verify for authentication\n"
        report += "* Forward security against quantum attacks\n\n"

        report += "KEY STATUS:\n"
        report += "-" * 12 + "\n"
        ed25519_fp = hashlib.sha3_256(self.my_public_key).hexdigest()[:16]
        dilithium_fp = hashlib.sha3_256(self.my_dilithium_public).hexdigest()[:16]
        report += f"Ed25519 fingerprint: {ed25519_fp}...\n"
        report += f"Dilithium fingerprint: {dilithium_fp}...\n"

        if os.path.exists(PEER_CERT_FILE):
            with open(PEER_CERT_FILE, "rb") as f:
                peer_ed25519 = f.read()
            peer_ed25519_fp = hashlib.sha3_256(peer_ed25519).hexdigest()[:16]
            report += f"Peer Ed25519 fingerprint: {peer_ed25519_fp}...\n"
        else:
            report += "Peer Ed25519: NOT CONFIGURED\n"

        if os.path.exists(PEER_DILITHIUM_PUB_FILE):
            with open(PEER_DILITHIUM_PUB_FILE, "rb") as f:
                peer_dilithium = f.read()
            peer_dilithium_fp = hashlib.sha3_256(peer_dilithium).hexdigest()[:16]
            report += f"Peer Dilithium fingerprint: {peer_dilithium_fp}...\n"
        else:
            report += "Peer Dilithium: NOT CONFIGURED\n"

        report += "\nSECURITY FEATURES:\n"
        report += "-" * 18 + "\n"
        report += "* Rate limiting and DoS protection\n"
        report += "* Secure random number generation\n"
        report += "* Constant-time comparisons\n"
        report += "* Memory-safe operations\n"
        report += "* Atomic file operations\n"
        report += "* Certificate pinning\n"
        report += "* Key destruction on exit\n"
        report += "* Hybrid signature integrity verification\n\n"

        report += "CONNECTION STATUS:\n"
        report += "-" * 18 + "\n"
        if self.connected:
            report += f"Status: SECURE HYBRID CONNECTION ACTIVE\n"
            report += f"Role: {'Server' if self.is_server else 'Client'}\n"
            if self.session_start_time:
                duration = int(time.time() - self.session_start_time)
                report += f"Session Duration: {duration}s\n"
        else:
            report += "Status: DISCONNECTED\n"

        report += "\nPAD STATUS:\n"
        report += "-" * 12 + "\n"
        if self.pad_manager:
            remaining = self.pad_manager.remaining_bytes()
            total = os.path.getsize(self.pad_manager.pad_path)
            used_percent = ((total - remaining) / total * 100) if total > 0 else 0

            report += f"Pad Size: {total // (1024 * 1024)}MB\n"
            report += f"Remaining: {remaining // (1024 * 1024)}MB ({100 - used_percent:.1f}%)\n"
            report += f"Current Offset: {self.pad_manager.current_offset()}\n"
            report += f"Sequence Number: {self.pad_manager.current_sequence()}\n"

            if remaining < 1024 * 1024:
                report += "WARNING: Low pad remaining\n"
        else:
            report += "NO PAD LOADED - INSECURE\n"

        report += "\nRECOMMENDATIONS:\n"
        report += "-" * 15 + "\n"
        report += "• Exchange hybrid key fingerprints securely\n"
        report += "• Verify both Ed25519 AND Dilithium keys out-of-band\n"
        report += "• Monitor pad usage and generate new pads\n"
        report += "• Keep post-quantum libraries updated\n"
        report += "• Use only on quantum-safe environments\n"

        return report

    def show_trusted_certs(self):
        """Display trusted TLS certificates"""
        cert_store_path = os.path.join(TLS_TRUSTED_CERTS_DIR, TLS_CERT_STORE)

        if not os.path.exists(cert_store_path):
            messagebox.showinfo("Trusted Certificates", "No trusted certificates found.")
            return

        try:
            with open(cert_store_path, 'r') as f:
                certs = json.load(f)

            if not certs:
                messagebox.showinfo("Trusted Certificates", "No trusted certificates found.")
                return

            cert_window = tk.Toplevel(self.root)
            cert_window.title("Trusted TLS Certificates")
            cert_window.geometry("900x600")
            cert_window.transient(self.root)

            frame = ttk.Frame(cert_window)
            frame.pack(fill="both", expand=True, padx=10, pady=10)

            text_widget = scrolledtext.ScrolledText(frame, font=("Consolas", 9))
            text_widget.pack(fill="both", expand=True)

            content = "TRUSTED TLS CERTIFICATES\n" + "=" * 80 + "\n\n"

            for host_port, cert_data in certs.items():
                content += f"Host: {host_port}\n"
                content += f"Fingerprint: {cert_data['fingerprint']}\n"
                content += f"Trusted Since: {cert_data['timestamp']}\n"

                try:
                    cert_der = base64.b64decode(cert_data['cert_der'])
                    cert = x509.load_der_x509_certificate(cert_der)
                    content += f"Subject: {cert.subject.rfc4514_string()}\n"
                    content += f"Issuer: {cert.issuer.rfc4514_string()}\n"
                    content += f"Valid Until: {cert.not_valid_after}\n"
                except Exception:
                    pass

                content += "-" * 80 + "\n\n"

            text_widget.insert("1.0", content)
            text_widget.config(state="disabled")

            ttk.Button(frame, text="Close", command=cert_window.destroy).pack(pady=(10, 0))

        except Exception as e:
            messagebox.showerror("Error", f"Could not load certificate store: {e}")

    def clear_cert_store(self):
        """Clear all trusted certificates with confirmation"""
        result = messagebox.askyesno(
            "Clear Certificate Store",
            "This will remove ALL trusted TLS certificates!\n\n"
            "You will need to re-approve certificates on next connection.\n\n"
            "This action cannot be undone. Continue?",
            icon='warning'
        )

        if result:
            try:
                cert_store_path = os.path.join(TLS_TRUSTED_CERTS_DIR, TLS_CERT_STORE)
                if os.path.exists(cert_store_path):
                    SecureAtomicOperations.secure_delete(cert_store_path)

                self.log("Cleared TLS certificate store", "SUCCESS")
                messagebox.showinfo("Success", "Certificate store cleared securely.")

            except Exception as e:
                self.log(f"Error clearing certificate store: {e}", "ERROR")
                messagebox.showerror("Error", f"Could not clear certificate store: {e}")

    def show_key_fingerprints(self):
        """Display hybrid cryptographic key fingerprints"""
        try:
            my_ed25519_fp = hashlib.sha3_256(self.my_public_key).hexdigest()
            my_dilithium_fp = hashlib.sha3_256(self.my_dilithium_public).hexdigest()

            peer_ed25519_fp = "Not available"
            peer_dilithium_fp = "Not available"

            if os.path.exists(PEER_CERT_FILE):
                with open(PEER_CERT_FILE, "rb") as f:
                    peer_ed25519_key = f.read()
                peer_ed25519_fp = hashlib.sha3_256(peer_ed25519_key).hexdigest()

            if os.path.exists(PEER_DILITHIUM_PUB_FILE):
                with open(PEER_DILITHIUM_PUB_FILE, "rb") as f:
                    peer_dilithium_key = f.read()
                peer_dilithium_fp = hashlib.sha3_256(peer_dilithium_key).hexdigest()

            fp_window = tk.Toplevel(self.root)
            fp_window.title("Hybrid Cryptographic Key Fingerprints")
            fp_window.geometry("900x500")
            fp_window.transient(self.root)

            main_frame = ttk.Frame(fp_window, padding="20")
            main_frame.pack(fill="both", expand=True)

            ttk.Label(main_frame, text="Hybrid Key Fingerprints",
                      font=("", 14, "bold")).pack(pady=(0, 20))

            # Your keys
            ttk.Label(main_frame, text="Your Ed25519 Public Key:",
                      font=("", 11, "bold")).pack(anchor="w")

            my_ed25519_text = tk.Text(main_frame, height=3, font=("Consolas", 10))
            my_ed25519_text.pack(fill="x", pady=(5, 10))
            my_ed25519_text.insert("1.0", my_ed25519_fp)
            my_ed25519_text.config(state="disabled")

            ttk.Label(main_frame, text="Your Dilithium2 Public Key:",
                      font=("", 11, "bold")).pack(anchor="w")

            my_dilithium_text = tk.Text(main_frame, height=3, font=("Consolas", 10))
            my_dilithium_text.pack(fill="x", pady=(5, 15))
            my_dilithium_text.insert("1.0", my_dilithium_fp)
            my_dilithium_text.config(state="disabled")

            # Peer keys
            ttk.Label(main_frame, text="Peer Ed25519 Public Key:",
                      font=("", 11, "bold")).pack(anchor="w")

            peer_ed25519_text = tk.Text(main_frame, height=3, font=("Consolas", 10))
            peer_ed25519_text.pack(fill="x", pady=(5, 10))
            peer_ed25519_text.insert("1.0", peer_ed25519_fp)
            peer_ed25519_text.config(state="disabled")

            ttk.Label(main_frame, text="Peer Dilithium2 Public Key:",
                      font=("", 11, "bold")).pack(anchor="w")

            peer_dilithium_text = tk.Text(main_frame, height=3, font=("Consolas", 10))
            peer_dilithium_text.pack(fill="x", pady=(5, 15))
            peer_dilithium_text.insert("1.0", peer_dilithium_fp)
            peer_dilithium_text.config(state="disabled")

            warning_label = ttk.Label(
                main_frame,
                text="WARNING: VERIFY BOTH fingerprints through a secure channel before trusting!",
                font=("", 10, "bold"),
                foreground="red"
            )
            warning_label.pack(pady=(10, 0))

            ttk.Button(main_frame, text="Close",
                       command=fp_window.destroy).pack(pady=(20, 0))

        except Exception as e:
            messagebox.showerror("Error", f"Could not display key fingerprints: {e}")

    def connect(self):
        """Initiate secure connection with hybrid signature validation"""
        if self.connected:
            self.disconnect()
            return

        if not self.pad_manager:
            messagebox.showerror("Error",
                                 "Load or generate a One-Time Pad before connecting!\n\n"
                                 "The pad provides perfect secrecy and is required for secure communication.")
            return

        remaining_bytes = self.pad_manager.remaining_bytes()
        if remaining_bytes < 64 * 1024:
            messagebox.showerror("Error",
                                 "Insufficient pad remaining!\n\n"
                                 "Generate a new pad or load a different one.")
            return

        try:
            host = self.host_entry.get().strip()
            port = int(self.port_entry.get().strip())

            if not host or port < 1 or port > 65535:
                raise ValueError("Invalid host or port")

        except ValueError as e:
            messagebox.showerror("Error", f"Invalid connection parameters: {e}")
            return

        self.connect_btn.config(text="Connecting...", state="disabled")
        self.send_btn.config(state="disabled")

        threading.Thread(target=self._connect_thread, args=(host, port), daemon=True).start()

    def _connect_thread(self, host: str, port: int):
        """Secure connection thread with hybrid signature authentication"""
        connection_id = secrets.token_hex(8)

        try:
            self.update_status(f"Connecting to {host}:{port}...")

            for layer in self.security_labels:
                self.update_security_layer(layer, False)

            client_success = False
            try:
                if not self.connection_manager.can_accept_connection(host):
                    raise ConnectionError("Too many connections from this host")

                sock = socket.create_connection((host, port), timeout=CONNECTION_TIMEOUT)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

                tls_context = SecureTLSManager.create_secure_context(is_server=False)
                tls_sock = tls_context.wrap_socket(sock, server_hostname=None)

                peer_cert = tls_sock.getpeercert(binary_form=True)
                trusted, message = SecureTLSManager.verify_certificate_trust(host, port, peer_cert)

                if not trusted:
                    tls_sock.close()
                    self.update_status(f"Certificate not trusted: {message}")
                    return

                self.tls_connection = tls_sock
                self.is_server = False
                self.connection_manager.register_connection(connection_id, host)
                client_success = True
                self.log("Connected as CLIENT - TLS handshake successful", "SUCCESS")

            except (ConnectionRefusedError, socket.timeout, OSError) as e:
                if not client_success:
                    self.log(f"Client connection failed: {e}, starting server...")

                    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    server_sock.bind((host, port))
                    server_sock.listen(1)
                    server_sock.settimeout(CONNECTION_TIMEOUT * 2)

                    self.log(f"Server listening on {host}:{port}...")
                    client_sock, addr = server_sock.accept()
                    server_sock.close()

                    if not self.connection_manager.can_accept_connection(addr[0]):
                        client_sock.close()
                        raise ConnectionError("Too many connections from client IP")

                    tls_context = SecureTLSManager.create_secure_context(is_server=True)
                    tls_sock = tls_context.wrap_socket(client_sock, server_side=True)

                    peer_cert = tls_sock.getpeercert(binary_form=True)
                    trusted, message = SecureTLSManager.verify_certificate_trust(addr[0], addr[1], peer_cert)

                    if not trusted:
                        tls_sock.close()
                        self.update_status(f"Client certificate not trusted: {message}")
                        return

                    self.tls_connection = tls_sock
                    self.is_server = True
                    self.connection_manager.register_connection(connection_id, addr[0])
                    self.log(f"Client connected from {addr} - TLS handshake successful", "SUCCESS")

            self.update_security_layer("TLS 1.3", True)

            if not self._perform_hybrid_mutual_auth():
                return

            self.update_security_layer("Ed25519", True)
            self.update_security_layer("Dilithium2", True)

            aes_key = self._perform_key_exchange()
            if not aes_key:
                return

            self.update_security_layer("ECDHE", True)
            self.update_security_layer("Kyber512", True)
            self.update_security_layer("AES-GCM", True)
            self.update_security_layer("HMAC-SHA3", True)
            self.update_security_layer("Anti-Replay", True)

            hmac_key = self.key_exchange.get_session_key('hmac')
            auth_key = self.key_exchange.get_session_key('auth')

            self.message_protocol = SecureMessageProtocol(aes_key, hmac_key, auth_key, self.pad_manager)
            self.message_protocol.app_instance = self
            self.connected = True
            self.session_start_time = time.time()
            self.update_status("SECURE HYBRID CONNECTION ESTABLISHED - All layers active")

            self.root.after(0, lambda: [
                self.send_btn.config(state="normal"),
                self.connect_btn.config(text="Disconnect", state="normal"),
                self.update_session_info()
            ])

            self.log("All hybrid security layers activated", "SUCCESS")
            threading.Thread(target=self._receive_thread, daemon=True).start()

        except Exception as e:
            self.log(f"Connection error: {e}", "ERROR")
            self.update_status(f"Connection failed: {e}")
            self._cleanup_connection()
        finally:
            self.connection_manager.unregister_connection(connection_id)

    def _perform_hybrid_mutual_auth(self) -> bool:
        """Perform hybrid Ed25519 + Dilithium mutual authentication"""
        try:
            self.log("Starting hybrid Ed25519 + Dilithium mutual authentication...")

            auth_timeout = time.time() + 30
            self.tls_connection.settimeout(5.0)

            # Send our hybrid public keys (Ed25519 + Dilithium)
            hybrid_pub_data = (struct.pack("!H", len(self.my_public_key)) + self.my_public_key +
                               struct.pack("!H", len(self.my_dilithium_public)) + self.my_dilithium_public)

            self.tls_connection.sendall(struct.pack("!I", len(hybrid_pub_data)) + hybrid_pub_data)
            self.log("Sent hybrid public keys", "SUCCESS")

            if time.time() > auth_timeout:
                raise TimeoutError("Authentication timeout")

            # Receive peer hybrid public keys
            hybrid_data_len = struct.unpack("!I", self._recv_exact(4))[0]
            if hybrid_data_len > 10000:  # Safety check
                raise ProtocolError("Invalid hybrid key data length")

            hybrid_data = self._recv_exact(hybrid_data_len)

            pos = 0
            peer_ed25519_len = struct.unpack("!H", hybrid_data[pos:pos + 2])[0]
            pos += 2
            peer_ed25519_key = hybrid_data[pos:pos + peer_ed25519_len]
            pos += peer_ed25519_len

            peer_dilithium_len = struct.unpack("!H", hybrid_data[pos:pos + 2])[0]
            pos += 2
            peer_dilithium_key = hybrid_data[pos:pos + peer_dilithium_len]

            self.log(
                f"Received peer hybrid keys - Ed25519: {len(peer_ed25519_key)} bytes, Dilithium: {len(peer_dilithium_key)} bytes",
                "SUCCESS")

            # Verify peer keys against stored keys
            if os.path.exists(PEER_CERT_FILE):
                with open(PEER_CERT_FILE, "rb") as f:
                    stored_ed25519_key = f.read()
                ed25519_fp_stored = hashlib.sha3_256(stored_ed25519_key).hexdigest()
                ed25519_fp_received = hashlib.sha3_256(peer_ed25519_key).hexdigest()

                if constant_time.bytes_eq(ed25519_fp_stored.encode(), ed25519_fp_received.encode()):
                    self.log("Ed25519 peer key verified against stored key", "SUCCESS")
                else:
                    self.log("SECURITY ALERT: Ed25519 peer key mismatch - connection REJECTED!", "SECURITY")
                    return False
            else:
                self.log("No stored Ed25519 peer key found - connection REJECTED for security", "SECURITY")
                return False

            if os.path.exists(PEER_DILITHIUM_PUB_FILE):
                with open(PEER_DILITHIUM_PUB_FILE, "rb") as f:
                    stored_dilithium_key = f.read()
                dilithium_fp_stored = hashlib.sha3_256(stored_dilithium_key).hexdigest()
                dilithium_fp_received = hashlib.sha3_256(peer_dilithium_key).hexdigest()

                if constant_time.bytes_eq(dilithium_fp_stored.encode(), dilithium_fp_received.encode()):
                    self.log("Dilithium peer key verified against stored key", "SUCCESS")
                else:
                    self.log("SECURITY ALERT: Dilithium peer key mismatch - connection REJECTED!", "SECURITY")
                    return False
            else:
                self.log("No stored Dilithium peer key found - connection REJECTED for security", "SECURITY")
                return False

            # Challenge-response with hybrid signatures
            challenge = secrets.token_bytes(64)
            self.tls_connection.sendall(struct.pack("!H", len(challenge)) + challenge)

            peer_challenge_len = struct.unpack("!H", self._recv_exact(2))[0]
            if peer_challenge_len > 1000:
                raise ProtocolError("Invalid peer challenge length")

            peer_challenge = self._recv_exact(peer_challenge_len)

            # Create hybrid signature
            ed25519_signature = self.my_private_key.sign(peer_challenge)
            dilithium_signature = dilithium2.sign(peer_challenge, self.my_dilithium_private)

            hybrid_sig_data = (struct.pack("!H", len(ed25519_signature)) + ed25519_signature +
                               struct.pack("!H", len(dilithium_signature)) + dilithium_signature)

            self.tls_connection.sendall(struct.pack("!I", len(hybrid_sig_data)) + hybrid_sig_data)
            self.log("Sent hybrid signature for authentication", "SUCCESS")

            # Receive and verify peer hybrid signature
            peer_hybrid_sig_len = struct.unpack("!I", self._recv_exact(4))[0]
            if peer_hybrid_sig_len > 10000:
                raise ProtocolError("Invalid peer signature length")

            peer_hybrid_sig_data = self._recv_exact(peer_hybrid_sig_len)

            pos = 0
            peer_ed25519_sig_len = struct.unpack("!H", peer_hybrid_sig_data[pos:pos + 2])[0]
            pos += 2
            peer_ed25519_signature = peer_hybrid_sig_data[pos:pos + peer_ed25519_sig_len]
            pos += peer_ed25519_sig_len

            peer_dilithium_sig_len = struct.unpack("!H", peer_hybrid_sig_data[pos:pos + 2])[0]
            pos += 2
            peer_dilithium_signature = peer_hybrid_sig_data[pos:pos + peer_dilithium_sig_len]

            self.log(
                f"Received hybrid signature - Ed25519: {len(peer_ed25519_signature)} bytes, Dilithium: {len(peer_dilithium_signature)} bytes",
                "SUCCESS")

            # Verify both signatures
            try:
                peer_ed25519_obj = serialization.load_pem_public_key(peer_ed25519_key)
                peer_ed25519_obj.verify(peer_ed25519_signature, challenge)
                self.log("Ed25519 signature verification successful", "SUCCESS")
            except Exception as ex:
                raise CryptoError(f"Ed25519 signature verification failed: {ex}")

            try:
                dilithium2.verify(peer_dilithium_signature, challenge, peer_dilithium_key)
                self.log("Dilithium signature verification successful", "SUCCESS")
            except Exception as ex:
                raise CryptoError(f"Dilithium signature verification failed: {ex}")

            self.log("Hybrid Ed25519 + Dilithium mutual authentication successful", "SUCCESS")
            return True

        except Exception as e:
            self.log(f"Hybrid authentication failed: {e}", "ERROR")
            return False

    def _perform_key_exchange(self) -> Optional[bytes]:
        """Perform secure hybrid key exchange with hybrid signatures"""
        self.log("Entering _perform_key_exchange() with hybrid signatures", "DEBUG")
        try:
            self.log("Starting ECDHE + Kyber key exchange with hybrid authentication...", "INFO")

            # Load peer keys for key exchange
            with open(PEER_CERT_FILE, "rb") as f:
                peer_ed25519_key = f.read()

            with open(PEER_DILITHIUM_PUB_FILE, "rb") as f:
                peer_dilithium_key = f.read()

            self.log(
                f"Loaded peer keys - Ed25519: {len(peer_ed25519_key)} bytes, Dilithium: {len(peer_dilithium_key)} bytes",
                "DEBUG")

            self.key_exchange = KeyExchangeProtocol(
                self.tls_connection,
                self.my_private_key,
                peer_ed25519_key,
                self.my_dilithium_private,
                peer_dilithium_key
            )
            self.log("KeyExchangeProtocol initialized with hybrid signatures", "DEBUG")

            aes_key = self.key_exchange.perform_key_exchange(
                self.tls_connection, self.is_server, peer_ed25519_key, peer_dilithium_key
            )
            self.log("Hybrid key exchange successful", "SUCCESS")
            self.log(f"AES key length: {len(aes_key)} bytes", "DEBUG")
            return aes_key

        except Exception as e:
            self.log(f"Hybrid key exchange failed: {e}", "ERROR")
            return None

    def _recv_exact(self, n: int) -> bytes:
        """Receive exact number of bytes with timeout protection"""
        self.log(f"_recv_exact called, expecting {n} bytes", "DEBUG")
        buf = b""
        deadline = time.time() + CONNECTION_TIMEOUT

        while len(buf) < n:
            if time.time() > deadline:
                self.log("Timeout reached in _recv_exact()", "ERROR")
                raise TimeoutError("Connection timeout during receive")

            try:
                self.tls_connection.settimeout(5.0)
                chunk = self.tls_connection.recv(min(n - len(buf), 8192))
                self.log(f"Received chunk ({len(chunk)} bytes)", "DEBUG")
                if not chunk:
                    self.log("Connection closed unexpectedly during _recv_exact()", "ERROR")
                    raise ConnectionError("Connection closed unexpectedly")
                buf += chunk
            except socket.timeout:
                continue

        self.log(f"_recv_exact completed, total {len(buf)} bytes received", "DEBUG")
        return buf

    def send_message(self):
        """Send encrypted message with validation"""
        self.log("send_message() called", "DEBUG")
        if not self.connected or not self.message_protocol:
            self.log("No secure connection established!", "ERROR")
            messagebox.showerror("Error", "No secure connection established!")
            return

        message = self.message_entry.get().strip()
        self.log(f"Message from entry: '{message}'", "DEBUG")
        if not message:
            self.log("Message is empty, nothing to send", "DEBUG")
            return

        if len(message.encode('utf-8')) > MAX_MESSAGE_SIZE:
            self.log(f"Message too large! ({len(message.encode('utf-8'))} bytes)", "ERROR")
            messagebox.showerror("Error", f"Message too large! Maximum {MAX_MESSAGE_SIZE} bytes allowed.")
            return

        self.message_entry.delete(0, "end")
        self.log("Message entry cleared", "DEBUG")
        self.send_btn.config(state="disabled")
        self.log("Send button disabled", "DEBUG")

        threading.Thread(target=self._send_message_thread, args=(message,), daemon=True).start()
        self.log("Send thread started", "DEBUG")

    def _send_message_thread(self, message: str):
        """Thread for sending encrypted message"""
        self.log(f"_send_message_thread() started for message: '{message}'", "DEBUG")
        try:
            start_time = time.time()

            encrypted_payload = self.message_protocol.encrypt_message(message)
            total_packet_len = len(encrypted_payload)
            len_header = struct.pack("!I", total_packet_len)
            final_packet_to_send = len_header + encrypted_payload

            self.log(f"Message encrypted, length: {total_packet_len} bytes", "DEBUG")

            self.tls_connection.sendall(final_packet_to_send)
            self.log("Encrypted packet sent over TLS connection", "DEBUG")

            encrypt_time = (time.time() - start_time) * 1000
            self.log(f"[SENT] {message} (encrypted in {encrypt_time:.1f}ms)", "SUCCESS")
            self.update_pad_info()
            self.log("Pad info updated after sending message", "DEBUG")

        except RateLimitError:
            self.log("Rate limit exceeded - message rejected", "ERROR")
        except Exception as e:
            self.log(f"Error sending message: {e}", "ERROR")
        finally:
            self.root.after(0, lambda: self.send_btn.config(state="normal"))
            self.log("Send button re-enabled", "DEBUG")

    def _receive_thread(self):
        """Receive length-prefixed packets and decode them"""
        self.log("_receive_thread() started", "DEBUG")
        MAX_PACKET_SIZE = 70 * 1024
        try:
            while self.connected:
                try:
                    len_data = self._recv_exact(4)
                    total_packet_len = struct.unpack("!I", len_data)[0]

                    self.log(f"Header received. {total_packet_len} byte packet incoming.", "DEBUG")

                    if not (0 < total_packet_len <= MAX_PACKET_SIZE):
                        self.log(f"Invalid packet size: {total_packet_len} bytes.", "SECURITY")
                        raise ProtocolError("Invalid packet size received.")

                    full_packet = self._recv_exact(total_packet_len)
                    self.log(f"Full packet received ({len(full_packet)} bytes).", "DEBUG")

                    try:
                        plaintext = self.message_protocol.decrypt_message(full_packet)
                        self.log(f"[RECEIVED] {plaintext}", "SUCCESS")
                    except (CryptoError, ProtocolError) as e:
                        self.log(f"[DECRYPT FAILED] {e}. RAW: {full_packet.hex()}", "SECURITY")

                    self.update_pad_info()

                except (socket.timeout, ConnectionError, TimeoutError):
                    self.log("Connection issue, terminating receive thread.", "INFO")
                    break
                except ProtocolError as e:
                    self.log(f"Protocol error: {e}. Closing connection.", "SECURITY")
                    break

        except Exception as e:
            if self.connected:
                self.log(f"Unexpected error in receive thread: {e}", "ERROR")
        finally:
            self._cleanup_connection()
            self.log("Receive thread finished.", "DEBUG")

    def disconnect(self):
        """Gracefully disconnect with cleanup"""
        self.log("Disconnecting...", "INFO")
        self.connected = False
        self._cleanup_connection()

    def _cleanup_connection(self):
        """Clean up connection resources securely"""
        self.connected = False
        self.session_start_time = None

        try:
            if self.tls_connection:
                self.tls_connection.close()
        except:
            pass

        if self.key_exchange:
            self.key_exchange.destroy_keys()

        if self.message_protocol:
            self.message_protocol.destroy_keys()

        self.tls_connection = None
        self.message_protocol = None
        self.key_exchange = None

        self.root.after(0, lambda: [
            self.send_btn.config(state="disabled"),
            self.connect_btn.config(text="Connect", state="normal"),
            self.update_status("Disconnected"),
            self.session_info.config(text="No active session")
        ])

        for layer in self.security_labels:
            self.update_security_layer(layer, False)

        self.log("Disconnected and cleaned up securely", "INFO")

    def send_file(self):
        """Send any file type - JAVÍTOTT VERZIÓ"""
        if not self.connected:
            messagebox.showerror("Error", "Not connected!")
            return

        filepath = filedialog.askopenfilename(
            title="Select file to send",
            filetypes=[("All files", "*.*")]
        )

        if not filepath:
            return

        # Használjuk ugyanazt a logikát mint send_image
        self._send_file_common(filepath)

    def send_image(self):
        """Send image file - JAVÍTOTT VERZIÓ"""
        if not self.connected:
            messagebox.showerror("Error", "Not connected!")
            return

        filepath = filedialog.askopenfilename(
            title="Select image to send",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.gif *.bmp")]
        )

        if not filepath:
            return

        # Használjuk ugyanazt a logikát mint send_file
        self._send_file_common(filepath)

    def _send_file_common(self, filepath):
        """Közös fájlküldési logika - egyszerű és működő"""
        try:
            file_size = os.path.getsize(filepath)
            if file_size > 50 * 1024 * 1024:  # 50MB limit
                messagebox.showerror("Error", f"File too large! Maximum 50MB allowed.")
                return

            filename = Path(filepath).name
            self.log(f"Starting file send: {filename} ({file_size} bytes)", "INFO")

            def send_thread():
                try:
                    chunk_size = 32 * 1024

                    self.file_status_label.config(text="Preparing...")

                    # 1. Send FILE_START
                    header = {
                        "type": "FILE_START",
                        "filename": filename,
                        "size": file_size,
                        "chunks": (file_size + chunk_size - 1) // chunk_size
                    }

                    control_msg = f"__FILE_TRANSFER__{json.dumps(header)}"
                    encrypted_payload = self.message_protocol.encrypt_message(control_msg)
                    len_header = struct.pack("!I", len(encrypted_payload))
                    self.tls_connection.sendall(len_header + encrypted_payload)

                    self.log(f"Sent FILE_START for: {filename}", "SUCCESS")

                    # 2. Send chunks
                    with open(filepath, 'rb') as f:
                        chunk_num = 0
                        bytes_sent = 0

                        while bytes_sent < file_size:
                            chunk_data = f.read(chunk_size)
                            if not chunk_data:
                                break

                            # Compress chunk
                            compressed = zlib.compress(chunk_data)

                            chunk_msg = {
                                "type": "FILE_CHUNK",
                                "chunk_num": chunk_num,
                                "data": base64.b64encode(compressed).decode('ascii')
                            }

                            control_msg = f"__FILE_TRANSFER__{json.dumps(chunk_msg)}"
                            encrypted_payload = self.message_protocol.encrypt_message(control_msg)
                            len_header = struct.pack("!I", len(encrypted_payload))
                            self.tls_connection.sendall(len_header + encrypted_payload)

                            bytes_sent += len(chunk_data)
                            chunk_num += 1

                            # Update progress
                            progress = (bytes_sent / file_size) * 100
                            self.file_progress['value'] = progress
                            self.file_status_label.config(text=f"Sending: {progress:.1f}%")
                            self.root.update_idletasks()

                            # Small delay to prevent overwhelming
                            time.sleep(0.001)

                        self.log(f"Sent {chunk_num} chunks ({bytes_sent} bytes)", "SUCCESS")

                    # 3. Send FILE_END
                    end_msg = {"type": "FILE_END", "filename": filename}
                    control_msg = f"__FILE_TRANSFER__{json.dumps(end_msg)}"
                    encrypted_payload = self.message_protocol.encrypt_message(control_msg)
                    len_header = struct.pack("!I", len(encrypted_payload))
                    self.tls_connection.sendall(len_header + encrypted_payload)

                    self.log(f"File sent successfully: {filename}", "SUCCESS")

                except Exception as e:
                    self.log(f"Send error: {e}", "ERROR")
                    print(f"[DEBUG] Send thread error details: {e}")
                    import traceback
                    traceback.print_exc()

                finally:
                    # Reset progress in main thread
                    self.root.after(0, lambda: [
                        setattr(self.file_progress, 'value', 0),
                        self.file_status_label.config(text="Ready")
                    ])

            # Start send thread
            threading.Thread(target=send_thread, daemon=True).start()

        except Exception as e:
            messagebox.showerror("Error", f"Could not send file: {e}")
            print(f"[DEBUG] _send_file_common error: {e}")

def main():
    """Main application entry point with error handling"""
    try:
        root = tk.Tk()
        app = SecureChatApp(root)

        def handle_exception(exc_type, exc_value, exc_traceback):
            if issubclass(exc_type, KeyboardInterrupt):
                sys.__excepthook__(exc_type, exc_value, exc_traceback)
                return

            logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
            messagebox.showerror("Unexpected Error",
                                 f"An unexpected error occurred:\n{exc_type.__name__}: {exc_value}")

        sys.excepthook = handle_exception

        root.mainloop()

    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        messagebox.showerror("Startup Error", f"Could not start application:\n{e}")
        sys.exit(1)


if __name__ == "__main__":
    main()