import os
import base64
import time
import oqs

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# =====================================================
# FASTAPI CONFIG
# =====================================================

app = FastAPI(
    title="Post-Quantum Cryptography API",
    description="Kyber768 KEM + Dilithium3 Signatures using liboqs",
    version="1.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =====================================================
# REQUEST MODELS
# =====================================================

class KyberEncapRequest(BaseModel):
    public_key: str


class KyberDecapRequest(BaseModel):
    ciphertext: str
    private_key: str


class DilithiumSignRequest(BaseModel):
    message: str
    private_key: str  # Now required for signing


class DilithiumVerifyRequest(BaseModel):
    message: str
    signature: str
    public_key: str


# =====================================================
# ROOT
# =====================================================

@app.get("/")
def root():
    return {
        "service": "Post-Quantum Cryptography API",
        "kem": "Kyber768",
        "signature": "Dilithium3",
        "endpoints": {
            "kem_list": "/kem",
            "sig_list": "/sig",
            "kyber_keygen": "/kyber/keygen",
            "kyber_encap": "/kyber/encapsulate",
            "kyber_decap": "/kyber/decapsulate",
            "dilithium_keygen": "/dilithium/keygen",
            "dilithium_sign": "/dilithium/sign",
            "dilithium_verify": "/dilithium/verify"
        }
    }


# =====================================================
# SUPPORTED KEMS
# =====================================================

@app.get("/kem")
def get_supported_kems():
    try:
        return {
            "supported_kems": oqs.get_enabled_kem_mechanisms()
        }
    except Exception as e:
        raise HTTPException(500, str(e))


# =====================================================
# SUPPORTED SIGNATURE SCHEMES
# =====================================================

@app.get("/sig")
def get_supported_sigs():
    try:
        return {
            "supported_signatures": oqs.get_enabled_sig_mechanisms()
        }
    except Exception as e:
        raise HTTPException(500, str(e))


# =====================================================
# KYBER768 — KEY GENERATION
# =====================================================

@app.get("/kyber/keygen")
def kyber_keygen():
    try:
        with oqs.KeyEncapsulation("Kyber768") as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()

        return {
            "algorithm": "Kyber768",
            "public_key": base64.b64encode(public_key).decode(),
            "private_key": base64.b64encode(private_key).decode()
        }

    except Exception as e:
        raise HTTPException(500, str(e))


# =====================================================
# KYBER768 — ENCAPSULATION
# =====================================================

@app.post("/kyber/encapsulate")
def kyber_encapsulate(request: KyberEncapRequest):
    try:
        public_key = base64.b64decode(request.public_key)

        with oqs.KeyEncapsulation("Kyber768") as kem:
            start = time.time()
            ciphertext, shared_secret = kem.encap_secret(public_key)
            elapsed = time.time() - start

        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "shared_secret": base64.b64encode(shared_secret).decode(),
            "time_sec": round(elapsed, 6)
        }

    except Exception as e:
        raise HTTPException(500, str(e))


# =====================================================
# KYBER768 — DECAPSULATION
# =====================================================

@app.post("/kyber/decapsulate")
def kyber_decapsulate(request: KyberDecapRequest):
    try:
        ciphertext = base64.b64decode(request.ciphertext)
        private_key = base64.b64decode(request.private_key)

        with oqs.KeyEncapsulation(
            "Kyber768",
            secret_key=private_key
        ) as kem:
            start = time.time()
            shared_secret = kem.decap_secret(ciphertext)
            elapsed = time.time() - start

        return {
            "shared_secret": base64.b64encode(shared_secret).decode(),
            "time_sec": round(elapsed, 6)
        }

    except Exception as e:
        raise HTTPException(500, str(e))


# =====================================================
# DILITHIUM3 — KEY GENERATION
# =====================================================

@app.get("/dilithium/keygen")
def dilithium_keygen():
    """
    Generate a Dilithium3 keypair.
    Returns both public and private keys (base64 encoded).
    """
    try:
        with oqs.Signature("Dilithium3") as sig:
            public_key = sig.generate_keypair()
            private_key = sig.export_secret_key()

        return {
            "algorithm": "Dilithium3",
            "public_key": base64.b64encode(public_key).decode(),
            "private_key": base64.b64encode(private_key).decode()
        }

    except Exception as e:
        raise HTTPException(500, str(e))


# =====================================================
# DILITHIUM3 — SIGN
# =====================================================

@app.post("/dilithium/sign")
def dilithium_sign(request: DilithiumSignRequest):
    """
    Sign a message using the provided private key.
    The private key should come from /dilithium/keygen.
    """
    try:
        message = request.message.encode()
        private_key = base64.b64decode(request.private_key)

        with oqs.Signature("Dilithium3", secret_key=private_key) as sig:
            signature = sig.sign(message)

        return {
            "signature": base64.b64encode(signature).decode(),
            "message": request.message
        }

    except Exception as e:
        raise HTTPException(500, str(e))


# =====================================================
# DILITHIUM3 — VERIFY
# =====================================================

@app.post("/dilithium/verify")
def dilithium_verify(request: DilithiumVerifyRequest):
    try:
        message = request.message.encode()
        signature = base64.b64decode(request.signature)
        public_key = base64.b64decode(request.public_key)

        with oqs.Signature("Dilithium3") as verifier:
            valid = verifier.verify(message, signature, public_key)

        return {
            "valid": bool(valid),
            "message": request.message
        }

    except Exception as e:
        raise HTTPException(500, str(e))


# =====================================================
# LOCAL RUN
# =====================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000))
    )