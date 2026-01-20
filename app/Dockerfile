# ============================================
# OPTIMIZED DOCKERFILE FOR RENDER DEPLOYMENT
# Build time: ~5-8 minutes (vs 20+ minutes)
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

# Build liboqs with MINIMAL configuration (Kyber only)
WORKDIR /tmp
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DOQS_MINIMAL_BUILD=ON \
        -DOQS_ENABLE_KEM_KYBER_768=ON \
        -DOQS_ENABLE_KEM_KYBER_512=ON \
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

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:${PORT:-10000}/health')" || exit 1

# Start application with explicit port binding
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-10000} --workers 1 --log-level info"]