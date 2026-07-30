# Оракул ГОСТ в контейнере.
# ВАЖНО: контекст сборки — КОРЕНЬ проекта (..), чтобы взять gost.py оттуда:
#   docker build -f docker_hnp/Dockerfile -t gost-oracle .
# либо через docker compose (см. docker-compose.yml).
FROM python:3.12-slim

WORKDIR /app
RUN pip install --no-cache-dir gostcrypto

# gost.py берём из корня проекта (единый источник), оракул — из папки стенда.
COPY gost.py /app/gost.py
COPY docker_hnp/oracle_server.py /app/oracle_server.py

EXPOSE 31337
ENV GOST_CURVE=B \
    ORACLE_HOST=0.0.0.0 \
    ORACLE_PORT=31337

CMD ["python", "-u", "oracle_server.py"]
