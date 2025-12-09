FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    iproute2 \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install --no-cache-dir scapy dnslib netifaces

# Copy scripts
COPY fake_ntp_server.py /usr/local/bin/
COPY dns_sinkhole.py /usr/local/bin/
COPY env_manipulation_scan.sh /usr/local/bin/

RUN chmod +x /usr/local/bin/*.py /usr/local/bin/*.sh

# Create output directory
RUN mkdir -p /output/environment-manipulation

WORKDIR /

CMD ["/usr/local/bin/env_manipulation_scan.sh"]
