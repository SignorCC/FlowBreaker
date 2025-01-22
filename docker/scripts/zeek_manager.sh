#!/bin/bash

# Convert line endings to Unix style
sed -i 's/\r$//' /zeek_manager.sh

# Install necessary tools
apt-get update && apt-get install -y inotify-tools docker.io zip

# Function to cleanup uploads
cleanup_uploads() {
    total_size=$(du -sb /uploads | cut -f1)
    max_size=$((12 * 1024 * 1024 * 1024))
    if [ $total_size -gt $max_size ]; then
        oldest_file=$(ls -t /uploads | tail -1)
        rm /uploads/$oldest_file
        echo "Removed oldest file: $oldest_file"
    fi
}

# Function to run Zeek analysis
run_zeek_analysis() {
    file=$1
    echo "Running Zeek analysis on $file"
    cd /scripts && ./run_zeek_analysis.sh "$file"
}

# Function to zip Zeek logs
zip_zeek_logs() {
    folder=$1
    echo "New folder '$folder' detected in /zeek-logs"

    # Wait for console.log to appear
    while [ ! -f "/zeek-logs/$folder/console.log" ]; do
        sleep 3
    done

    echo "console.log found, assuming Zeek analysis is complete."

    cd /zeek-logs && zip -r "/zipped-logs/$folder.zip" "$folder"
    echo "Zipped '$folder' and moved to /zipped-logs"

    # Remove the original folder
    rm -rf "/zeek-logs/$folder"
    echo "Removed original folder '$folder'"
}

# Main loop
while true; do
    # Cleanup uploads
    cleanup_uploads

    # Watch for new files in uploads
    inotifywait -q -e create -e moved_to /uploads |
    while read path action file; do
        echo "The file '$file' appeared in directory '$path' via '$action'"
        run_zeek_analysis "$file"
    done &

    # Watch for new folders in zeek-logs
    inotifywait -q -e create -e moved_to /zeek-logs |
    while read path action folder; do
        if [ -d "/zeek-logs/$folder" ]; then
            zip_zeek_logs "$folder"
        fi
    done &

    wait
done
