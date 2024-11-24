#!/bin/bash

# Advanced SIEM Installation Script for Ubuntu
# Comprehensive Log Processing and SIEM Setup with Suricata and Winlogbeat

# Set global variables
LOG_CONVERSION_DIR="/opt/siem/log-conversion"
SIEM_CONFIG_DIR="/opt/siem/configs"
LOG_PROCESSOR_DIR="/opt/siem/log-processor"
SURICATA_LOG_DIR="/var/log/suricata"
WINLOGBEAT_CONFIG_DIR="/opt/siem/winlogbeat"

# [Previous logging setup function remains the same]
setup_logging() {
    mkdir -p /var/log/siem/conversion
    mkdir -p /var/log/siem/processing
    mkdir -p /var/log/siem/suricata
    
    cat > /etc/logrotate.d/siem-logs << EOF
/var/log/siem/conversion/*.log /var/log/siem/processing/*.log /var/log/siem/suricata/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 640 root adm
}
EOF
}

# Install and Configure Suricata
install_suricata() {
    echo "Installing Suricata IDS..."
    add-apt-repository ppa:oisf/suricata-stable -y
    apt-get update
    apt-get install -y suricata

    # Configure Suricata
    cat > /etc/suricata/suricata.yaml << EOF
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: ${SURICATA_LOG_DIR}/eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - ssh
        - flow
        - netflow
        - smtp
        - stats

af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

app-layer:
  protocols:
    tls:
      enabled: yes
    ssh:
      enabled: yes
    smtp:
      enabled: yes
    http:
      enabled: yes
EOF

    # Update Suricata rules
    suricata-update
    
    # Enable and start Suricata
    systemctl enable suricata
    systemctl start suricata
}

# Configure Winlogbeat Template
setup_winlogbeat_template() {
    mkdir -p $WINLOGBEAT_CONFIG_DIR
    
    cat > $WINLOGBEAT_CONFIG_DIR/winlogbeat.yml << EOF
winlogbeat.event_logs:
  - name: Application
    ignore_older: 72h
  - name: System
  - name: Security
    processors:
      - drop_events:
          when:
            or:
              - equals:
                  event_id: 4688
                  source_name: Microsoft-Windows-Security-Auditing
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Windows PowerShell
  - name: Microsoft-Windows-PowerShell/Operational

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~

output.elasticsearch:
  hosts: ["localhost:9200"]
  protocol: "http"
  username: "elastic"
  password: "your_elastic_password"
  indices:
    - index: "winlogbeat-%{[agent.version]}-%{+yyyy.MM.dd}"

setup.kibana:
  host: "localhost:5601"
EOF

    # Create installation instructions
    cat > $WINLOGBEAT_CONFIG_DIR/INSTALL_INSTRUCTIONS.txt << EOF
Winlogbeat Installation Instructions:

1. Download Winlogbeat from: https://www.elastic.co/downloads/beats/winlogbeat
2. Extract to C:\Program Files\Winlogbeat
3. Copy this configuration file to C:\Program Files\Winlogbeat\winlogbeat.yml
4. Install using PowerShell (as Administrator):
   PS> cd 'C:\Program Files\Winlogbeat'
   PS> .\install-service-winlogbeat.ps1

5. Start the service:
   PS> Start-Service winlogbeat
EOF
}

# Update Log Sources in Log Ingestion Script
create_log_ingestion_script() {
    cat > $SIEM_CONFIG_DIR/log_ingestion.sh << 'EOF'
#!/bin/bash

# Log Ingestion and Processing Master Script

# Directories
LOG_SOURCE_DIR="/var/log"
CONVERSION_DIR="/opt/siem/log-conversion"
PROCESSING_DIR="/opt/siem/log-processor"
OUTPUT_DIR="/opt/siem/processed-logs"
SURICATA_LOG_DIR="/var/log/suricata"

# Create output directories
mkdir -p "$OUTPUT_DIR/converted"
mkdir -p "$OUTPUT_DIR/processed"

# Extended Log sources to monitor
LOG_SOURCES=(
    "/var/log/syslog"
    "/var/log/auth.log"
    "/var/log/kern.log"
    "/var/log/apache2/access.log"
    "/var/log/nginx/access.log"
    "${SURICATA_LOG_DIR}/eve.json"
)

# Process each log source
for source in "${LOG_SOURCES[@]}"; do
    if [ -f "$source" ]; then
        filename=$(basename "$source")
        
        # Special handling for Suricata logs (already in JSON)
        if [[ "$source" == *"eve.json" ]]; then
            cp "$source" "$OUTPUT_DIR/converted/${filename}"
        else
            # Convert other logs
            "$CONVERSION_DIR/convert_logs.sh" "$source" "$OUTPUT_DIR/converted/${filename}.json" "syslog"
        fi
        
        # Process converted log
        "$PROCESSING_DIR/process_logs.py" "$OUTPUT_DIR/converted/${filename}.json" "$OUTPUT_DIR/processed/${filename}_processed.json"
    fi
done
EOF

    chmod +x $SIEM_CONFIG_DIR/log_ingestion.sh
}

# Update Filebeat Configuration
configure_filebeat() {
    # Install Filebeat
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list
    apt-get update
    apt-get install -y filebeat

    # Configure Filebeat with Suricata module
    cat > /etc/filebeat/filebeat.yml << EOF
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /opt/siem/processed-logs/converted/*.json
    - /opt/siem/processed-logs/processed/*.json
  json.keys_under_root: true
  json.add_error_key: true

- type: log
  enabled: true
  paths:
    - ${SURICATA_LOG_DIR}/eve.json
  json.keys_under_root: true
  tags: ["suricata"]

output.elasticsearch:
  hosts: ["localhost:9200"]
  username: "elastic"
  password: "your_elastic_password"

setup.kibana:
  host: "localhost:5601"

filebeat.modules:
  - module: suricata
    eve:
      enabled: true
      var.paths: ["${SURICATA_LOG_DIR}/eve.json"]
EOF

    # Enable necessary Filebeat modules
    filebeat modules enable system
    filebeat modules enable suricata

    # Start and enable Filebeat
    systemctl enable filebeat
    systemctl start filebeat
}

# Main Installation Function
main() {
    # Prerequisite checks
    if [[ $EUID -ne 0 ]]; then
       echo "This script must be run as root" 
       exit 1
    fi

    # Create necessary directories
    mkdir -p $LOG_CONVERSION_DIR
    mkdir -p $SIEM_CONFIG_DIR
    mkdir -p $LOG_PROCESSOR_DIR
    mkdir -p $SURICATA_LOG_DIR
    mkdir -p $WINLOGBEAT_CONFIG_DIR

    # Install dependencies
    apt-get update
    apt-get install -y \
        python3-pip \
        python3-dev \
        build-essential \
        jq \
        software-properties-common

    # Setup components
    setup_logging
    install_universal_log_converter
    setup_log_processing_pipeline
    install_suricata
    setup_winlogbeat_template
    create_log_ingestion_script
    configure_filebeat
    setup_log_processing_cron

    echo "SIEM Infrastructure with Suricata and Winlogbeat Support Deployed Successfully!"
    echo "Please check ${WINLOGBEAT_CONFIG_DIR}/INSTALL_INSTRUCTIONS.txt for Winlogbeat deployment steps on Windows hosts."
}

# Run the main function
main
