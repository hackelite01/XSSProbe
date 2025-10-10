# XSSProbe Docker Image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create results directory
RUN mkdir -p /app/results

# Set permissions
RUN chmod +x xssprobe.py

# Create non-root user for security
RUN useradd -m -u 1000 xssuser && chown -R xssuser:xssuser /app
USER xssuser

# Set entrypoint
ENTRYPOINT ["python3", "xssprobe.py"]

# Default command (can be overridden)
CMD ["--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import requests, bs4; print('Dependencies OK')" || exit 1

# Labels for metadata
LABEL maintainer="adityanageshsir <ppr0gr4m3rr@gmail.com>"
LABEL description="XSSProbe - Advanced XSS Vulnerability Scanner"
LABEL version="1.0"
LABEL repository="https://github.com/adityanageshsir/XSSProbe"