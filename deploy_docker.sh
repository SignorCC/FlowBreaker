#!/bin/bash

# Determine the privilege escalation command
if command -v doas >/dev/null 2>&1; then
    PRIV_CMD="doas"
elif command -v sudo >/dev/null 2>&1; then
    PRIV_CMD="sudo"
else
    echo "Neither doas nor sudo found. Please run this script as root."
    exit 1
fi

# Function to run commands with privilege escalation if not root
run_privileged() {
    if [ "$(id -u)" -ne 0 ]; then
        $PRIV_CMD "$@"
    else
        "$@"
    fi
}

# GitHub repository information
REPO_URL="https://github.com/SignorCC/FlowBreaker.git"
REPO_BRANCH="master"
DOCKER_DIR="docker"

# Create a temporary directory for cloning
TEMP_DIR=$(mktemp -d)

# Clone the repository
echo "Cloning repository..."
git clone --depth 1 --branch $REPO_BRANCH $REPO_URL $TEMP_DIR

# Check if the clone was successful
if [ $? -ne 0 ]; then
    echo "Failed to clone repository. Exiting."
    rm -rf $TEMP_DIR
    exit 1
fi

# Copy the required folders and file
echo "Copying required files and folders..."
cp -R $TEMP_DIR/$DOCKER_DIR/scripts .
cp -R $TEMP_DIR/$DOCKER_DIR/nginx .
cp $TEMP_DIR/$DOCKER_DIR/docker-compose.yml .

# Remove the temporary directory
rm -rf $TEMP_DIR

# Create necessary directories
echo "Creating directories..."
run_privileged mkdir -p ./uploads ./zeek-logs ./zipped-logs

# Set permissions
echo "Setting permissions..."
run_privileged chmod 775 ./nginx -R
run_privileged chmod 777 ./scripts -R
run_privileged chmod 777 ./uploads -R
run_privileged chmod 777 ./zeek-logs -R
run_privileged chmod 777 ./zipped-logs -R

# Run docker compose
echo "Please edit the docker-compose.yml then run docker compose up"

echo "Script completed."
