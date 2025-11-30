FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nmap \
    masscan \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    jq \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.24 (required by naabu)
RUN curl -LO https://go.dev/dl/go1.24.3.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.24.3.linux-amd64.tar.gz && \
    rm go1.24.3.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"
ENV GOPATH="/root/go"

# Install naabu
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Install rustscan
RUN wget https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb && \
    dpkg -i rustscan_2.1.1_amd64.deb || apt-get install -f -y && \
    rm rustscan_2.1.1_amd64.deb

COPY discovery_scan.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/discovery_scan.sh

WORKDIR /output

CMD ["/bin/bash"]
