# AdMob Mediation Tool — container image for Google Cloud Run (or any host).
FROM python:3.12-slim

# Don't write .pyc, stream logs unbuffered (so Cloud Run logs are live).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install deps first (better layer caching).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code + templates/static.
COPY flow.py .
COPY templates ./templates
COPY static ./static

# Cloud Run sends traffic to $PORT (defaults to 8080). Bind 0.0.0.0 so the
# container is reachable. Shell form so $PORT is expanded at runtime.
ENV PORT=8080
CMD exec uvicorn flow:app --host 0.0.0.0 --port ${PORT}
