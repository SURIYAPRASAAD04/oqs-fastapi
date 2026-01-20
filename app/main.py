import os
import time
import oqs
import base64

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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

# Add CORS middleware for web access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================
# UTIL FUNCTIONS
# ==========================

def derive_aes_keys(shared_secret):
    """Derive AES encryption key and IV from shared secret"""
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
    """Encrypt message using AES-256-CBC"""
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
    """Decrypt message using AES-256-CBC"""
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
    """Health check endpoint"""
    return {
        "status": "OK",
        "service": "Post-Quantum Cryptography API",
        "algorithm": "Kyber768 + AES-256",
        "endpoints": [
            "/",
            "/kem",
            "/encrypt",
            "/decrypt",
            "/docs"
        ]
    }


@app.get("/health")
def health_check():
    """Health check for monitoring"""
    return {"status": "healthy", "timestamp": time.time()}


@app.get("/kem")
def supported_kem():
    """Get list of supported Key Encapsulation Mechanisms"""
    try:
        kems = oqs.get_enabled_KEM_mechanisms()
        return {
            "supported_kem": kems,
            "count": len(kems),
            "using": "Kyber768"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching KEMs: {str(e)}")


@app.post("/encrypt")
def encrypt_data(request: EncryptRequest):
    """
    Hybrid Post-Quantum Encryption:
    1. Generate Kyber768 keypair
    2. Encapsulate shared secret with Kyber768
    3. Derive AES-256 key from shared secret
    4. Encrypt message with AES-256-CBC
    
    Returns: encrypted message, encrypted AES key, Kyber ciphertext, keys, IV
    """
    try:
        message_bytes = request.message.encode()

        # Generate random AES key and IV
        aes_key = os.urandom(32)
        aes_iv = os.urandom(16)

        # Kyber768 Key Encapsulation
        with oqs.KeyEncapsulation("Kyber768") as kem:
            # Generate Kyber keypair
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()

            # Encapsulate to get shared secret
            start = time.time()
            kyber_ciphertext, shared_secret = kem.encap_secret(public_key)
            kem_time = time.time() - start

            # Derive keys from shared secret
            enc_key, enc_iv = derive_aes_keys(shared_secret)

            # Encrypt the AES key with derived key
            cipher = Cipher(
                algorithms.AES(enc_key),
                modes.CFB(enc_iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted_aes_key = encryptor.update(aes_key) + encryptor.finalize()

            # Encrypt the actual message with AES
            encrypted_message = aes_encrypt(message_bytes, aes_key, aes_iv)

        return {
            "message_encrypted": base64.b64encode(encrypted_message).decode(),
            "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),
            "kyber_ciphertext": base64.b64encode(kyber_ciphertext).decode(),
            "public_key": base64.b64encode(public_key).decode(),
            "private_key": base64.b64encode(private_key).decode(),
            "iv": base64.b64encode(aes_iv).decode(),
            "kem_time_sec": round(kem_time, 6),
            "algorithm": "Kyber768 + AES-256-CBC"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Encryption error: {str(e)}")


@app.post("/decrypt")
def decrypt_data(request: DecryptRequest):
    """
    Hybrid Post-Quantum Decryption:
    1. Decapsulate Kyber768 ciphertext with private key to get shared secret
    2. Derive AES-256 key from shared secret
    3. Decrypt the encrypted AES key
    4. Decrypt the message with decrypted AES key
    
    Returns: decrypted message
    """
    try:
        # Decode base64 inputs
        encrypted_message = base64.b64decode(request.ciphertext)
        encrypted_aes_key = base64.b64decode(request.encrypted_aes_key)
        kyber_ciphertext = base64.b64decode(request.kyber_ciphertext)
        private_key = base64.b64decode(request.private_key)
        iv = base64.b64decode(request.iv)

        # Kyber768 Decapsulation
        with oqs.KeyEncapsulation("Kyber768", secret_key=private_key) as kem:
            # Decapsulate to get shared secret
            shared_secret = kem.decap_secret(kyber_ciphertext)

            # Derive keys from shared secret
            dec_key, dec_iv = derive_aes_keys(shared_secret)

            # Decrypt the AES key
            cipher = Cipher(
                algorithms.AES(dec_key),
                modes.CFB(dec_iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            aes_key = decryptor.update(encrypted_aes_key) + decryptor.finalize()

            # Decrypt the actual message
            decrypted_message = aes_decrypt(encrypted_message, aes_key, iv)

        return {
            "decrypted_message": decrypted_message.decode(),
            "algorithm": "Kyber768 + AES-256-CBC"
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption error: {str(e)}")


# For local testing
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)