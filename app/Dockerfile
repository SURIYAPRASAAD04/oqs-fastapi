# ===== Base image =====
FROM python:3.11-slim

# Prevent Python writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install OS packages needed for building liboqs
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    cmake \
    ninja-build \
    pkg-config \
    libssl-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ===== Build liboqs from source =====
WORKDIR /opt
# Use shallow clone for faster build
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git
WORKDIR /opt/liboqs
RUN mkdir build && cd build && \
    cmake -GNinja -DOQS_USE_OPENSSL=ON .. && \
    ninja && ninja install && ldconfig

# Clean up build files to reduce image size
RUN cd /opt && rm -rf liboqs

# ===== Python dependencies =====
WORKDIR /app

# Copy only requirements first for Docker caching
COPY requirements.txt .

# Install Python deps
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Install the Python wrapper for liboqs
RUN pip install --no-cache-dir git+https://github.com/open-quantum-safe/liboqs-python.git@main

# ===== Copy the FastAPI app =====
COPY main.py .

# CRITICAL FIX: Render provides PORT environment variable
# We must bind to $PORT, not hardcoded 8000
EXPOSE 10000

# Run Uvicorn with PORT environment variable from Render
# The ${PORT:-10000} means: use $PORT if set, otherwise default to 10000
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-10000}