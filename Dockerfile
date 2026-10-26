FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

# Every service runs unprivileged; all listening ports are above 1024.
RUN useradd --system --uid 10001 --create-home plcsentinel
USER plcsentinel

EXPOSE 5020 802 10200 10202 4840 1102

CMD ["python3", "-m", "plcsentinel.ops.soc_dashboard"]
