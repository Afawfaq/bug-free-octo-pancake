FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    gcc \
    libssl-dev \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install --no-cache-dir \
    scapy \
    impacket \
    pysmb

# Copy honeypot scripts
COPY smb_honeypot.py /usr/local/bin/smb_honeypot.py
COPY ipp_honeypot.py /usr/local/bin/ipp_honeypot.py
COPY chromecast_honeypot.py /usr/local/bin/chromecast_honeypot.py
COPY ssdp_honeypot.py /usr/local/bin/ssdp_honeypot.py
COPY alert_system.py /usr/local/bin/alert_system.py
COPY deception_scan.sh /usr/local/bin/deception_scan.sh

# Make scripts executable
RUN chmod +x /usr/local/bin/*.py /usr/local/bin/*.sh

# Set working directory
WORKDIR /output

# Default command
CMD ["/usr/local/bin/deception_scan.sh", "/output/deception", "3600"]
