FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    git \
    nmap \
    jq \
    dnsutils \
    openssl \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install Python libraries
RUN pip3 install requests beautifulsoup4 packaging

COPY patch_scan.sh /usr/local/bin/
COPY firmware_fingerprinter.py /usr/local/bin/
COPY update_reachability.py /usr/local/bin/
COPY cve_matcher.py /usr/local/bin/
COPY aging_scorer.py /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh /usr/local/bin/*.py

WORKDIR /output

CMD ["/bin/bash"]
