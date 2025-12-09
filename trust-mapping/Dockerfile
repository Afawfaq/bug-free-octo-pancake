FROM ubuntu:22.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    smbclient \
    ldap-utils \
    net-tools \
    dnsutils \
    avahi-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install --no-cache-dir \
    scapy \
    networkx \
    matplotlib \
    python-nmap \
    pysmb

# Create working directory
WORKDIR /usr/local/bin

# Copy scripts
COPY *.py /usr/local/bin/
COPY *.sh /usr/local/bin/

# Make scripts executable
RUN chmod +x /usr/local/bin/*.py /usr/local/bin/*.sh

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/trust_mapping_scan.sh"]
