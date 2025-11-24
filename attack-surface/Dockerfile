FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    hping3 \
    tcpdump \
    tshark \
    netcat-openbsd \
    dnsutils \
    curl \
    wget \
    jq \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install scapy requests python-nmap netifaces

COPY stress_profiler.py /usr/local/bin/
COPY forgotten_protocols.py /usr/local/bin/
COPY dependency_mapper.py /usr/local/bin/
COPY entropy_analyzer.py /usr/local/bin/
COPY ignored_ports.py /usr/local/bin/
COPY trust_assumptions.py /usr/local/bin/
COPY attack_surface_scan.sh /usr/local/bin/

RUN chmod +x /usr/local/bin/*.sh /usr/local/bin/*.py

WORKDIR /output

CMD ["/bin/bash"]
