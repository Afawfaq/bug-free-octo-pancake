FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    tshark \
    tcpdump \
    wireshark-common \
    net-tools \
    iproute2 \
    iftop \
    nethogs \
    jq \
    graphviz \
    && rm -rf /var/lib/apt/lists/*

# Install Python libraries for traffic analysis and visualization
RUN pip3 install scapy netifaces numpy scipy matplotlib networkx pandas

COPY data_flow_scan.sh /usr/local/bin/
COPY traffic_baseline.py /usr/local/bin/
COPY chatter_fingerprinter.py /usr/local/bin/
COPY anomaly_detector.py /usr/local/bin/
COPY flow_graph_builder.py /usr/local/bin/
COPY time_series_analyzer.py /usr/local/bin/
RUN chmod +x /usr/local/bin/*.sh /usr/local/bin/*.py

WORKDIR /output

CMD ["/bin/bash"]
