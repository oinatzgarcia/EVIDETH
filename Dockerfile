# EVIDETH Backend - Dockerfile
# =============================
# Imagen para FastAPI + PostgreSQL + verificación criptográfica

FROM python:3.11-slim

LABEL maintainer="EVIDETH <oinatz.garcia@opendeusto.es>"
LABEL description="Backend de verificación forense de vídeo con ECDSA P-256"

# Variables de entorno para Python
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Instalar dependencias del sistema
# ffmpeg: procesamiento de vídeo (extracción de segmentos)
# libpq-dev: cliente PostgreSQL
# gcc: compilación de extensiones Python (cryptography, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Directorio de trabajo
WORKDIR /app

# Copiar requirements e instalar dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código fuente
COPY app/ ./app/
COPY frontend/ ./frontend/
COPY alembic/ ./alembic/
COPY alembic.ini .

# Usuario no-root para seguridad
RUN useradd -m -u 1000 evideth && chown -R evideth:evideth /app
USER evideth

# Puerto del servidor
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8000/api/v1/health', timeout=5)"

# Comando por defecto (puede ser sobreescrito en docker-compose)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
