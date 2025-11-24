FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    docker.io \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install docker

COPY run.py /usr/local/bin/orchestrator
RUN chmod +x /usr/local/bin/orchestrator

WORKDIR /output

CMD ["python3", "/usr/local/bin/orchestrator"]
