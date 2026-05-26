# Identity Research for Agent Management Using SPIFFE — Management Portal
# Build context: repo root (az acr build --file portal/Dockerfile .)
FROM python:3.12-slim

WORKDIR /app/portal

# Install dependencies
COPY portal/requirements.txt /tmp/portal-requirements.txt
RUN pip install --no-cache-dir -r /tmp/portal-requirements.txt

# Copy application code (no-cache build ensures fresh layers)
ARG CACHE_BUST=1
ARG BUILD_VERSION=dev
ENV PORTAL_VERSION=${BUILD_VERSION}

COPY portal /app/portal
COPY src/shared /app/src/shared

EXPOSE 8550

CMD ["uvicorn", "server:create_app", "--factory", "--host", "0.0.0.0", "--port", "8550"]
