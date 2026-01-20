# Use a lightweight Python base image
FROM python:3.11-slim

# -------------------------------
# Install system dependencies
# -------------------------------
RUN apt-get update && apt-get install -y \
    git \
    cmake \
    build-essential \
    ninja-build \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# -------------------------------
# Build and install liboqs
# -------------------------------
WORKDIR /opt
RUN git clone https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake -DOQS_USE_OPENSSL=ON .. && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# -------------------------------
# Set working directory for FastAPI
# -------------------------------
WORKDIR /app

# Copy Python requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy FastAPI app code
COPY app ./app

# Expose FastAPI port
EXPOSE 8000

# Command to run the FastAPI server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
