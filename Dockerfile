# ===== Base image =====
FROM python:3.11-slim

# ===== Environment variables =====
ENV PYTHONUNBUFFERED=1
ENV OQS_DIR=/usr/local

# ===== System dependencies =====
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    cmake \
    ninja-build \
    pkg-config \
    libssl-dev \
    wget \
    unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ===== Build liboqs from source =====
WORKDIR /tmp
RUN git clone --branch main https://github.com/open-quantum-safe/liboqs.git
WORKDIR /tmp/liboqs
RUN mkdir build && cd build && cmake -GNinja -DCMAKE_BUILD_TYPE=Release .. && ninja && ninja install

# ===== Python dependencies =====
WORKDIR /app
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# ===== Install pyoqs from source =====
RUN pip install --no-cache-dir git+https://github.com/open-quantum-safe/liboqs-python.git@main

# ===== Copy app code =====
COPY . /app

# ===== Expose port =====
EXPOSE 8000

# ===== Run FastAPI app =====
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
