FROM ubuntu:22.04

# Install dependencies - all free and local
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    rsyslog \
    logrotate \
    cron \
    libnotify-bin \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages - minimal, free alternatives
RUN pip3 install --no-cache-dir \
    schedule

# Create directories
RUN mkdir -p /var/log /etc/lan-recon /output/monitor

# Copy monitor scripts
COPY monitor_daemon.py /usr/local/bin/
COPY alert_integration.py /usr/local/bin/
COPY monitor_start.sh /usr/local/bin/
COPY monitor.conf.example /etc/lan-recon/

RUN chmod +x /usr/local/bin/monitor_daemon.py \
    /usr/local/bin/alert_integration.py \
    /usr/local/bin/monitor_start.sh

# Setup syslog
RUN echo 'local0.* /var/log/lan-recon-monitor.log' >> /etc/rsyslog.conf

# Create non-root user
RUN useradd -m -s /bin/bash monitor && \
    chown -R monitor:monitor /output /var/log/lan-recon*

# Start as root to access rsyslog, then drop privileges
CMD ["/usr/local/bin/monitor_start.sh"]
