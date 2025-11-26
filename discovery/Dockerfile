FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    nmap \
    masscan \
    curl \
    wget \
    git \
    golang-go \
    python3 \
    python3-pip \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install naabu
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
ENV PATH="/root/go/bin:${PATH}"

# Install rustscan
RUN wget https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb && \
    dpkg -i rustscan_2.1.1_amd64.deb || apt-get install -f -y && \
    rm rustscan_2.1.1_amd64.deb

COPY discovery_scan.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/discovery_scan.sh

WORKDIR /output

CMD ["/bin/bash"]
