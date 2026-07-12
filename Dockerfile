# Janus — Quantum-Aware Cyber-Fraud Fusion
# Container image running the FastAPI service as a non-root user.
FROM python:3.13-slim

# Don't buffer stdout/stderr; don't write .pyc files.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Create an unprivileged user to run the service.
RUN useradd --create-home --shell /usr/sbin/nologin janus

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project.
COPY . .

# Drop privileges: everything below runs as the non-root 'janus' user.
RUN chown -R janus:janus /app
USER janus

EXPOSE 8000

CMD ["uvicorn", "janus.api:app", "--host", "0.0.0.0", "--port", "8000"]
