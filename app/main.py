import os
import time
import oqs
import base64

from fastapi import FastAPI
from pydantic import BaseModel

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


app = FastAPI(
    title="Post Quantum Crypto API",
    description="Kyber768 + AES-256 Hybrid Encryption using liboqs",
    version="1.0"
)

# ==========================
# UTIL FUNCTIONS
# ==========================

def derive_aes_keys(shared_secret):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=48,
        salt=None,
        info=b"pqc-aes-derivation",
        backend=default_backend()
    )
    key_material = hkdf.derive(shared_secret)
    return key_material[:32], key_material[32:48]


def aes_encrypt(message: bytes, key: bytes, iv: bytes):
    padder = padding.PKCS7(128).padder()
    padded = padder.update(message) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes):
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ==========================
# REQUEST MODELS
# ==========================

class EncryptRequest(BaseModel):
    message: str


class DecryptRequest(BaseModel):
    ciphertext: str
    encrypted_aes_key: str
    kyber_ciphertext: str
    private_key: str
    iv: str


# ==========================
# ROUTES
# ==========================

@app.get("/")
def root():
    return {
        "status": "running",
        "algorithm": "Kyber768 + AES-256",
        "lib": "Open Quantum Safe (liboqs)"
    }


@app.get("/kem")
def supported_kem():
    return {
        "supported_kem": oqs.get_enabled_KEM_mechanisms()
    }


@app.post("/encrypt")
def encrypt_data(request: EncryptRequest):
    """
    Hybrid PQ Encryption:
    Kyber768 → Shared Secret → AES-256
    """

    message_bytes = request.message.encode()

    aes_key = os.urandom(32)
    aes_iv = os.urandom(16)

    with oqs.KeyEncapsulation("Kyber768") as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()

        start = time.time()
        kyber_ciphertext, shared_secret = kem.encap_secret(public_key)
        kem_time = time.time() - start

        enc_key, enc_iv = derive_aes_keys(shared_secret)

        cipher = Cipher(
            algorithms.AES(enc_key),
            modes.CFB(enc_iv),
            backend=default_backend()
        )

        encryptor = cipher.encryptor()
        encrypted_aes_key = encryptor.update(aes_key) + encryptor.finalize()

        encrypted_message = aes_encrypt(message_bytes, aes_key, aes_iv)

    return {
        "message_encrypted": base64.b64encode(encrypted_message).decode(),
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
        "kyber_ciphertext": base64.b64encode(kyber_ciphertext).decode(),
        "public_key": base64.b64encode(public_key).decode(),
        "private_key": base64.b64encode(private_key).decode(),
        "iv": base64.b64encode(aes_iv).decode(),
        "kem_time_sec": round(kem_time, 6)
    }


@app.post("/decrypt")
def decrypt_data(request: DecryptRequest):

    encrypted_message = base64.b64decode(request.ciphertext)
    encrypted_aes_key = base64.b64decode(request.encrypted_aes_key)
    kyber_ciphertext = base64.b64decode(request.kyber_ciphertext)
    private_key = base64.b64decode(request.private_key)
    iv = base64.b64decode(request.iv)

    with oqs.KeyEncapsulation("Kyber768", secret_key=private_key) as kem:
        shared_secret = kem.decap_secret(kyber_ciphertext)

        dec_key, dec_iv = derive_aes_keys(shared_secret)

        cipher = Cipher(
            algorithms.AES(dec_key),
            modes.CFB(dec_iv),
            backend=default_backend()
        )

        decryptor = cipher.decryptor()
        aes_key = decryptor.update(encrypted_aes_key) + decryptor.finalize()

        decrypted_message = aes_decrypt(encrypted_message, aes_key, iv)

    return {
        "decrypted_message": decrypted_message.decode()
    }
