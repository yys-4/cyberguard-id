# Stage 1: builder image
FROM python:3.9-slim AS builder

WORKDIR /build

# Copy dependency manifest
COPY requirements.txt .

# Install dependencies into a virtual environment for transfer to runtime image
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: runtime image
FROM python:3.9-slim

WORKDIR /app

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Run as non-root for safer defaults
RUN useradd -m appuser

# Copy app source, models, and calibration dataset
COPY --chown=appuser:appuser src/ src/
COPY --chown=appuser:appuser models/ models/
COPY --chown=appuser:appuser data/processed/processed_cyber_data.csv data/processed/processed_cyber_data.csv

# Ensure logs directory exists and is writable by app user
RUN mkdir -p logs && chown -R appuser:appuser logs

USER appuser

EXPOSE 8000

# Start FastAPI app
CMD ["uvicorn", "src.app:app", "--host", "0.0.0.0", "--port", "8000"]
