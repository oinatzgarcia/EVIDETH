# EVIDETH Camera Simulator
# Imagen base: Python 3.11 slim para minimizar tamaño
FROM python:3.11-slim

# Dependencias del sistema necesarias para OpenCV headless y libmagic
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instalar dependencias Python primero (cachea mejor en rebuilds)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código
COPY simulator.py .

# Directorio para clave privada (montado como volumen para persistencia)
RUN mkdir -p /keys

# Usuario sin privilegios por seguridad
RUN useradd -r -s /bin/false evideth && \
    chown -R evideth:evideth /app /keys
USER evideth

CMD ["python", "-u", "simulator.py"]
