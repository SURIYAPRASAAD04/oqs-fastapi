# ============================================
# WORKING DOCKERFILE FOR RENDER DEPLOYMENT
# Uses specific liboqs version and selective algorithm build
# ============================================

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Install ALL dependencies in one layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    cmake \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Build liboqs - NEW METHOD (without OQS_MINIMAL_BUILD)
# We disable most algorithms except Kyber
WORKDIR /tmp
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF \
        -DOQS_ENABLE_KEM_FRODOKEM=OFF \
        -DOQS_ENABLE_KEM_NTRUPRIME=OFF \
        -DOQS_ENABLE_KEM_BIKE=OFF \
        -DOQS_ENABLE_KEM_HQC=OFF \
        -DOQS_ENABLE_SIG_DILITHIUM=ON \
        -DOQS_ENABLE_SIG_FALCON=OFF \
        -DOQS_ENABLE_SIG_SPHINCS=OFF \
        -DOQS_ENABLE_KEM_KYBER_512=ON \
        -DOQS_ENABLE_KEM_KYBER_768=ON \
        -DOQS_ENABLE_KEM_KYBER_1024=ON \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        .. && \
    make -j4 && \
    make install && \
    ldconfig && \
    cd /tmp && rm -rf liboqs

# Setup application directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir liboqs-python

# Copy application code
COPY main.py .

# Clean up build dependencies to reduce image size
RUN apt-get remove -y git build-essential cmake && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

EXPOSE 10000

# Start application with explicit port binding
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-10000} --workers 1 --log-level info"]