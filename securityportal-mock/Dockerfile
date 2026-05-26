# Security Portal Mock — Agent Risk Signal Source
# Build context: repo root (az acr build --file securityportal-mock/Dockerfile .)
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY securityportal-mock/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (no-cache build ensures fresh layers)
ARG CACHE_BUST=1
ARG BUILD_VERSION=dev
ENV PORTAL_VERSION=${BUILD_VERSION}
COPY securityportal-mock/server.py /app/server.py
COPY securityportal-mock/index.html /app/index.html

# Copy shared modules (imported by server.py)
COPY src/shared/jwt_validator.py /app/jwt_validator.py
COPY src/shared/graph_token.py /app/graph_token.py

EXPOSE 8560

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8560"]
