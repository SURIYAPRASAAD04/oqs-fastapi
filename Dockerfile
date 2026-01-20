# ===== Base image =====
FROM python:3.11-slim

# Prevent Python writing .pyc files
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

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
RUN git clone https://github.com/open-quantum-safe/liboqs.git
WORKDIR /opt/liboqs
RUN mkdir build && cd build && \
    cmake -GNinja -DOQS_USE_OPENSSL=ON .. && \
    ninja && ninja install && ldconfig

# ===== Python dependencies =====
WORKDIR /app
# Copy only requirements first for Docker caching
COPY requirements.txt .

# Install Python deps except pyoqs from git
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Install the Python wrapper for liboqs
RUN pip install --no-cache-dir git+https://github.com/open-quantum-safe/liboqs-python.git@main

# ===== Copy the FastAPI app =====
COPY . /app

# Expose FastAPI port
EXPOSE 8000

# Run Uvicorn pointing to app.main
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
