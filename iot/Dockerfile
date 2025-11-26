FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    git \
    miniupnpc \
    gupnp-tools \
    jq \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install Python libraries for IoT/UPnP
RUN pip3 install requests pychromecast upnpy

# Clone useful IoT tools
RUN git clone https://github.com/initstring/uptux /opt/uptux 2>&1 || true

COPY iot_scan.sh /usr/local/bin/
COPY chromecast_enum.py /usr/local/bin/
COPY dlna_enum.py /usr/local/bin/
COPY printer_enum.py /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh /usr/local/bin/*.py

WORKDIR /output

CMD ["/bin/bash"]
