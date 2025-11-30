FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    snmp \
    smbclient \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.24 (required by httpx)
RUN curl -LO https://go.dev/dl/go1.24.3.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.24.3.linux-amd64.tar.gz && \
    rm go1.24.3.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# Install httpx
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install whatweb
RUN git clone https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && \
    cd /opt/whatweb && \
    chmod +x whatweb

ENV PATH="/opt/whatweb:${PATH}"

COPY fingerprint_scan.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/fingerprint_scan.sh

WORKDIR /output

CMD ["/bin/bash"]
