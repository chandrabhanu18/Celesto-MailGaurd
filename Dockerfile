FROM python:3.12-slim

# Install system utilities (curl for container healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency definition and install Python packages
COPY pyproject.toml .
RUN pip install --no-cache-dir \
    fastapi>=0.115.0 \
    uvicorn>=0.32.0 \
    pydantic>=2.9.0 \
    sqlalchemy>=2.0.35 \
    aiosqlite>=0.20.0 \
    asyncpg>=0.29.0 \
    greenlet>=3.0.0 \
    python-dotenv>=1.0.1 \
    httpx>=0.27.0 \
    celesto>=0.1.4

# Copy application source code and resources
COPY backend/ backend/
COPY seeds/ seeds/
COPY reports/ reports/
COPY logs/ logs/

ENV PYTHONPATH=/app
ENV API_PORT=8080
ENV HOST=0.0.0.0

EXPOSE 8080

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8080"]
