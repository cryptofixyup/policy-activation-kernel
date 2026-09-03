FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/nonexistent

RUN groupadd \
        --gid 10001 \
        appgroup \
    && useradd \
        --uid 10001 \
        --gid appgroup \
        --no-create-home \
        --shell /usr/sbin/nologin \
        appuser

WORKDIR /app

COPY requirements.txt /app/requirements.txt

RUN pip install \
        --no-cache-dir \
        --requirement /app/requirements.txt \
    && rm -f /app/requirements.txt

COPY lambda_dlp/index.py /app/index.py
COPY lambda_dlp/server.py /app/server.py

RUN chown -R root:root /app \
    && chmod 0555 /app \
    && chmod 0444 /app/index.py \
    && chmod 0444 /app/server.py

USER 10001:10001

EXPOSE 8080

ENTRYPOINT [
    "uvicorn",
    "server:app",
    "--host",
    "0.0.0.0",
    "--port",
    "8080",
    "--no-access-log"
]
