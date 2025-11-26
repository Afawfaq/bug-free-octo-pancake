FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    wget \
    git \
    golang-go \
    python3 \
    python3-pip \
    snmp \
    smbclient \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install httpx
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install whatweb
RUN git clone https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    cd /opt/whatweb && \
    chmod +x whatweb

ENV PATH="/root/go/bin:/opt/whatweb:${PATH}"

COPY fingerprint_scan.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/fingerprint_scan.sh

WORKDIR /output

CMD ["/bin/bash"]
