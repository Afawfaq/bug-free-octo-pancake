FROM projectdiscovery/nuclei:latest

USER root

RUN apk add --no-cache bash curl jq git

# Update nuclei templates
RUN nuclei -update-templates

# Copy custom templates
COPY custom-templates/ /root/nuclei-templates/custom/

COPY nuclei_scan.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/nuclei_scan.sh

WORKDIR /output

CMD ["/bin/bash"]
