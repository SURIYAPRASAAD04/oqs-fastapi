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
    description="ML-KEM-768 (Kyber768) + ML-DSA-65 (Dilithium3) using liboqs",
    version="2.0.0"
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

class KemEncapRequest(BaseModel):
    public_key: str


class KemDecapRequest(BaseModel):
    ciphertext: str
    private_key: str


class DsaSignRequest(BaseModel):
    message: str
    private_key: str


class DsaVerifyRequest(BaseModel):
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
        "kem": "ML-KEM-768 (NIST FIPS 203 - formerly Kyber768)",
        "signature": "ML-DSA-65 (NIST FIPS 204 - formerly Dilithium3)",
        "note": "Using NIST-standardized algorithm names",
        "endpoints": {
            "kem_list": "/kem",
            "sig_list": "/sig",
            "ml_kem_keygen": "/ml-kem/keygen",
            "ml_kem_encap": "/ml-kem/encapsulate",
            "ml_kem_decap": "/ml-kem/decapsulate",
            "ml_dsa_keygen": "/ml-dsa/keygen",
            "ml_dsa_sign": "/ml-dsa/sign",
            "ml_dsa_verify": "/ml-dsa/verify",
            "legacy_endpoints": {
                "kyber_keygen": "/kyber/keygen (deprecated, use /ml-kem/keygen)",
                "dilithium_keygen": "/dilithium/keygen (deprecated, use /ml-dsa/keygen)"
            }
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
# ML-KEM-768 (Kyber768) — KEY GENERATION
# =====================================================

@app.get("/ml-kem/keygen")
def ml_kem_keygen():
    try:
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()

        return {
            "algorithm": "ML-KEM-768",
            "standard": "NIST FIPS 203",
            "formerly": "Kyber768",
            "public_key": base64.b64encode(public_key).decode(),
            "private_key": base64.b64encode(private_key).decode()
        }

    except Exception as e:
        raise HTTPException(500, str(e))


# Legacy endpoint for backward compatibility
@app.get("/kyber/keygen")
def kyber_keygen():
    return ml_kem_keygen()


# =====================================================
# ML-KEM-768 — ENCAPSULATION
# =====================================================

@app.post("/ml-kem/encapsulate")
def ml_kem_encapsulate(request: KemEncapRequest):
    try:
        public_key = base64.b64decode(request.public_key)

        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            start = time.time()
            ciphertext, shared_secret = kem.encap_secret(public_key)
            elapsed = time.time() - start

        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "shared_secret": base64.b64encode(shared_secret).decode(),
            "time_sec": round(elapsed, 6),
            "algorithm": "ML-KEM-768"
        }

    except Exception as e:
        raise HTTPException(500, str(e))


# Legacy endpoint
@app.post("/kyber/encapsulate")
def kyber_encapsulate(request: KemEncapRequest):
    return ml_kem_encapsulate(request)


# =====================================================
# ML-KEM-768 — DECAPSULATION
# =====================================================

@app.post("/ml-kem/decapsulate")
def ml_kem_decapsulate(request: KemDecapRequest):
    try:
        ciphertext = base64.b64decode(request.ciphertext)
        private_key = base64.b64decode(request.private_key)

        with oqs.KeyEncapsulation(
            "ML-KEM-768",
            secret_key=private_key
        ) as kem:
            start = time.time()
            shared_secret = kem.decap_secret(ciphertext)
            elapsed = time.time() - start

        return {
            "shared_secret": base64.b64encode(shared_secret).decode(),
            "time_sec": round(elapsed, 6),
            "algorithm": "ML-KEM-768"
        }

    except Exception as e:
        raise HTTPException(500, str(e))


# Legacy endpoint
@app.post("/kyber/decapsulate")
def kyber_decapsulate(request: KemDecapRequest):
    return ml_kem_decapsulate(request)


# =====================================================
# ML-DSA-65 (Dilithium3) — KEY GENERATION
# =====================================================

@app.get("/ml-dsa/keygen")
def ml_dsa_keygen():
    """
    Generate an ML-DSA-65 keypair (formerly Dilithium3).
    Returns both public and private keys (base64 encoded).
    """
    try:
        with oqs.Signature("ML-DSA-65") as sig:
            public_key = sig.generate_keypair()
            private_key = sig.export_secret_key()

        return {
            "algorithm": "ML-DSA-65",
            "standard": "NIST FIPS 204",
            "formerly": "Dilithium3",
            "public_key": base64.b64encode(public_key).decode(),
            "private_key": base64.b64encode(private_key).decode()
        }

    except Exception as e:
        raise HTTPException(500, str(e))


# Legacy endpoint
@app.get("/dilithium/keygen")
def dilithium_keygen():
    return ml_dsa_keygen()


# =====================================================
# ML-DSA-65 — SIGN
# =====================================================

@app.post("/ml-dsa/sign")
def ml_dsa_sign(request: DsaSignRequest):
    """
    Sign a message using ML-DSA-65 with the provided private key.
    The private key should come from /ml-dsa/keygen.
    """
    try:
        message = request.message.encode()
        private_key = base64.b64decode(request.private_key)

        with oqs.Signature("ML-DSA-65", secret_key=private_key) as sig:
            start = time.time()
            signature = sig.sign(message)
            elapsed = time.time() - start

        return {
            "signature": base64.b64encode(signature).decode(),
            "message": request.message,
            "time_sec": round(elapsed, 6),
            "algorithm": "ML-DSA-65"
        }

    except Exception as e:
        raise HTTPException(500, str(e))


# Legacy endpoint
@app.post("/dilithium/sign")
def dilithium_sign(request: DsaSignRequest):
    return ml_dsa_sign(request)


# =====================================================
# ML-DSA-65 — VERIFY
# =====================================================

@app.post("/ml-dsa/verify")
def ml_dsa_verify(request: DsaVerifyRequest):
    """
    Verify an ML-DSA-65 signature.
    """
    try:
        message = request.message.encode()
        signature = base64.b64decode(request.signature)
        public_key = base64.b64decode(request.public_key)

        with oqs.Signature("ML-DSA-65") as verifier:
            start = time.time()
            valid = verifier.verify(message, signature, public_key)
            elapsed = time.time() - start

        return {
            "valid": bool(valid),
            "message": request.message,
            "time_sec": round(elapsed, 6),
            "algorithm": "ML-DSA-65"
        }

    except Exception as e:
        raise HTTPException(500, str(e))


# Legacy endpoint
@app.post("/dilithium/verify")
def dilithium_verify(request: DsaVerifyRequest):
    return ml_dsa_verify(request)


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