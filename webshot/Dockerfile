FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    chromium-browser \
    python3 \
    python3-pip \
    git \
    wget \
    curl \
    jq \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Aquatone
RUN wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip && \
    unzip aquatone_linux_amd64_1.7.0.zip && \
    mv aquatone /usr/local/bin/ && \
    chmod +x /usr/local/bin/aquatone && \
    rm aquatone_linux_amd64_1.7.0.zip

# Install EyeWitness dependencies
RUN pip3 install selenium pillow

# Clone EyeWitness
RUN git clone https://github.com/FortyNorthSecurity/EyeWitness.git /opt/EyeWitness

COPY webshot_scan.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/webshot_scan.sh

WORKDIR /output

CMD ["/bin/bash"]
