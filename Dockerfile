# dbug - Automated Stealth Android Dynamic Analysis, Threat Intelligence & AppSec Toolkit
# Multi-platform Cloud Container (Ubuntu 22.04 LTS)

FROM ubuntu:22.04

LABEL maintainer="dbug research team"
LABEL description="Isolated Android Dynamic Analysis, Executable Debugger & Threat Intelligence Sandbox"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV TZ=UTC

# Install system dependencies, Android tools, QEMU user emulation, packet inspection tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    git \
    curl \
    wget \
    ca-certificates \
    android-tools-adb \
    qemu-user-static \
    tcpdump \
    tshark \
    iproute2 \
    iptables \
    kmod \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Install Python requirements
COPY requirements.txt /workspace/
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt

# Copy repository source tree
COPY . /workspace/

# Ensure scripts and tools have executable permissions
RUN chmod +x orchestrator.py \
    scripts/*.sh \
    device_cloaking/*.sh \
    network_capture/*.sh \
    sample_triage/*.py \
    samples/*.py 2>/dev/null || true

# Pre-generate defensive mock samples for immediate out-of-the-box readiness
RUN python3 samples/build_samples.py

# Default entrypoint runs orchestrator in virtual cloud sandbox mode
ENTRYPOINT ["python3", "orchestrator.py"]
CMD ["--mode", "virtual", "--profile", "all"]
