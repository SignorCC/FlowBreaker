#!/bin/bash

# Docker container name
CONTAINER_NAME="zeek-zeek-1"

# Parse the .pcap file name from the script argument
PCAP_FILE="$1"

# Check if a file name was provided
if [ -z "$PCAP_FILE" ]; then
    echo "Error: No .pcap file specified. Usage: $0 <pcap_file>"
    exit 1
fi

# Check if the file exists in the uploads directory
if [ ! -f "/uploads/$PCAP_FILE" ]; then
    echo "Error: File $PCAP_FILE not found in /uploads/"
    exit 1
fi

# Create a unique output directory name using the pcap filename and timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
PCAP_NAME=$(basename "$PCAP_FILE" .pcap)
OUTPUT_DIR="/zeek-logs/${PCAP_NAME}_$TIMESTAMP"

# Create the output directory in the container
docker exec $CONTAINER_NAME mkdir -p $OUTPUT_DIR
if [ $? -ne 0 ]; then
    echo "Error: Failed to create output directory in the container"
    exit 1
fi

# Create a temporary Zeek script with the redef statements
TEMP_SCRIPT=$(mktemp)
cat << EOF > $TEMP_SCRIPT
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl

redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
redef Log::default_rotation_interval = 0secs;
EOF

# Copy the temporary script to the container
docker cp $TEMP_SCRIPT $CONTAINER_NAME:$OUTPUT_DIR/temp_script.zeek

# Zeek command with additional scripts and options
ZEEK_COMMAND="cd $OUTPUT_DIR && zeek -C -r /uploads/$PCAP_FILE local \
  ./temp_script.zeek \
  protocols/conn/known-services \
  protocols/http/detect-sqli \
  protocols/ssh/detect-bruteforcing \
  policy/frameworks/files/hash-all-files \
  policy/frameworks/intel/seen \
  policy/misc/detect-traceroute \
  policy/protocols/conn/vlan-logging \
  policy/protocols/dns/auth-addl \
  policy/protocols/http/var-extraction-cookies \
  policy/protocols/ssl/validate-certs \
  policy/protocols/ssl/log-hostcerts-only"

# Run the Zeek command inside the Docker container and capture the output
docker exec $CONTAINER_NAME bash -c "$ZEEK_COMMAND" > /tmp/zeek_output.log 2>&1

# Copy the output log to the container
docker cp /tmp/zeek_output.log $CONTAINER_NAME:$OUTPUT_DIR/console.log

# Remove the temporary files
rm $TEMP_SCRIPT /tmp/zeek_output.log
docker exec $CONTAINER_NAME rm $OUTPUT_DIR/temp_script.zeek

# Check if the console.log file was created successfully
if docker exec $CONTAINER_NAME test -f $OUTPUT_DIR/console.log; then
    echo "Zeek analysis completed successfully for $PCAP_FILE"
    echo "Output files are available in the Docker container at $OUTPUT_DIR"
else
    echo "Error: Zeek analysis failed for $PCAP_FILE"
    echo "console.log was not created in the output directory"
    exit 1
fi

# List the contents of the output directory
echo "Contents of $OUTPUT_DIR:"
docker exec $CONTAINER_NAME ls -l $OUTPUT_DIR