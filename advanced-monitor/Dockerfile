FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    tshark \
    tcpdump \
    dnsutils \
    openssl \
    nmap \
    jq \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install scapy pyshark python-nmap cryptography requests paho-mqtt

COPY pki_monitor.py /usr/local/bin/
COPY dhcp_profiler.py /usr/local/bin/
COPY dns_mapper.py /usr/local/bin/
COPY metadata_extractor.py /usr/local/bin/
COPY protocol_guilt.py /usr/local/bin/
COPY advanced_scan.sh /usr/local/bin/

RUN chmod +x /usr/local/bin/*.sh /usr/local/bin/*.py

WORKDIR /output

CMD ["/bin/bash"]
