FROM python:3.12-slim

LABEL maintainer="Krishna Chaithanya Yada"
LABEL description="DockerShield - Docker Image Security Scanner"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dockershield.py .

ENTRYPOINT ["python", "dockershield.py"]
