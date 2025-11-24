FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    tshark \
    p0f \
    arp-scan \
    avahi-utils \
    gupnp-tools \
    miniupnpc \
    tcpdump \
    net-tools \
    iproute2 \
    python3 \
    python3-pip \
    curl \
    wget \
    jq \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install scapy netifaces

COPY passive_scan.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/passive_scan.sh

WORKDIR /output

CMD ["/bin/bash"]
