FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    aircrack-ng \
    wireless-tools \
    net-tools \
    iproute2 \
    pciutils \
    usbutils \
    iw \
    rfkill \
    bluez \
    bluez-tools \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install Python libraries
RUN pip3 install scapy netifaces

COPY wifi_scan.sh /usr/local/bin/
COPY spectrum_scanner.py /usr/local/bin/
COPY pmkid_harvester.py /usr/local/bin/
COPY wps_attacker.py /usr/local/bin/
COPY evil_twin_analyzer.py /usr/local/bin/
COPY ble_scanner.py /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh /usr/local/bin/*.py

WORKDIR /output

CMD ["/bin/bash"]
