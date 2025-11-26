FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    graphviz \
    wkhtmltopdf \
    jq \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install jinja2 networkx matplotlib pydot weasyprint

COPY report_builder.py /usr/local/bin/
COPY report_template.html /templates/
RUN chmod +x /usr/local/bin/report_builder.py

WORKDIR /output

CMD ["/bin/bash"]
