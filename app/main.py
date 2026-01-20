import os
import time
import base64
import oqs

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# ==========================================================
# FASTAPI APP
# ==========================================================

app = FastAPI(
    title="Post-Quantum Cryptography API",
    description="Kyber768 KEM + Dilithium3 Signatures using liboqs",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================================
# REQUEST MODELS
# ==========================================================

class EncryptRequest(BaseModel):
    message: str


class DecryptRequest(BaseModel):
    ciphertext: str
    private_key: str


class SignRequest(BaseModel):
    message: str


class VerifyRequest(BaseModel):
    message: str
    signature: str
    public_key: str


# ==========================================================
# ROOT
# ==========================================================

@app.get("/")
def root():
    return {
        "status": "OK",
        "pqc": "liboqs",
        "kem": "Kyber768",
        "signature": "Dilithium3",
        "endpoints": [
            "/kem",
            "/kyber/generate",
            "/kyber/encapsulate",
            "/kyber/decapsulate",
            "/dilithium/generate",
            "/dilithium/sign",
            "/dilithium/verify",
            "/docs"
        ]
    }


# ==========================================================
# SUPPORTED KEMS
# ==========================================================

@app.get("/kem")
def list_kems():
    try:
        return {
            "supported_kems": oqs.get_enabled_kem_mechanisms()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================================
# KYBER — KEY GENERATION
# ==========================================================

@app.get("/kyber/generate")
def kyber_generate():
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
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================================
# KYBER — ENCAPSULATION
# ==========================================================

@app.post("/kyber/encapsulate")
def kyber_encapsulate(public_key: str):
    try:
        public_key = base64.b64decode(public_key)

        with oqs.KeyEncapsulation("Kyber768") as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)

        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "shared_secret": base64.b64encode(shared_secret).decode()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================================
# KYBER — DECAPSULATION
# ==========================================================

@app.post("/kyber/decapsulate")
def kyber_decapsulate(ciphertext: str, private_key: str):
    try:
        ciphertext = base64.b64decode(ciphertext)
        private_key = base64.b64decode(private_key)

        with oqs.KeyEncapsulation(
            "Kyber768",
            secret_key=private_key
        ) as kem:
            shared_secret = kem.decap_secret(ciphertext)

        return {
            "shared_secret": base64.b64encode(shared_secret).decode()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================================
# DILITHIUM — KEY GENERATION
# ==========================================================

@app.get("/dilithium/generate")
def dilithium_generate():
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
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================================
# DILITHIUM — SIGN
# ==========================================================

@app.post("/dilithium/sign")
def dilithium_sign(request: SignRequest):
    try:
        message = request.message.encode()

        with oqs.Signature("Dilithium3") as sig:
            sig.generate_keypair()
            signature = sig.sign(message)

        return {
            "signature": base64.b64encode(signature).decode()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================================
# DILITHIUM — VERIFY
# ==========================================================

@app.post("/dilithium/verify")
def dilithium_verify(request: VerifyRequest):
    try:
        message = request.message.encode()
        signature = base64.b64decode(request.signature)
        public_key = base64.b64decode(request.public_key)

        with oqs.Signature("Dilithium3") as verifier:
            valid = verifier.verify(message, signature, public_key)

        return {
            "valid": bool(valid)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================================
# LOCAL RUN
# ==========================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000))
    )
