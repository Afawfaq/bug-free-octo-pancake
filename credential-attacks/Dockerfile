FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    git \
    nmap \
    hydra \
    medusa \
    smbclient \
    ftp \
    telnet \
    snmp \
    netcat-openbsd \
    tcpdump \
    tshark \
    john \
    hashcat \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install Python libraries
RUN pip3 install requests scapy paramiko pysnmp impacket

COPY credential_scan.sh /usr/local/bin/
COPY default_creds_tester.py /usr/local/bin/
COPY cleartext_sniffer.py /usr/local/bin/
COPY ssh_harvester.py /usr/local/bin/
COPY default_creds_db.json /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh /usr/local/bin/*.py

WORKDIR /output

CMD ["/bin/bash"]
