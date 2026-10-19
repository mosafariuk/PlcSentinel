FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY .venv/requirements.txt requirements.txt 2>/dev/null || COPY README.md .
RUN pip install --no-cache-dir \
    pymodbus==3.16.1 \
    python-snap7==3.2.1 \
    asyncua==2.1.0 \
    cryptography==50.0.2 \
    scapy==2.8.0 \
    requests==2.34.2

COPY . /app

EXPOSE 5020 10200 4840 1102

CMD ["python3", "soc_dashboard.py"]
