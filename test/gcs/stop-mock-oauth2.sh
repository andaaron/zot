#!/bin/bash
# Helper script to stop the mock OAuth2 server
# This stops the server and cleans up all temporary files

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common configuration
. "$SCRIPT_DIR/mock-oauth2-config.sh"

# Check if server is running
if [ ! -f "$PID_FILE" ]; then
    echo "Mock OAuth2 server is not running (PID file not found: $PID_FILE)"
    exit 0
fi

PID=$(cat "$PID_FILE")

# Check if the process is actually running
if ! ps -p "$PID" > /dev/null 2>&1; then
    echo "Mock OAuth2 server process not found (PID: $PID)"
    echo "Cleaning up stale PID file..."
    rm -f "$PID_FILE"
    # Clean up directory if empty or only contains stale files
    if [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
    exit 0
fi

# Stop the server
echo "Stopping mock OAuth2 server (PID: $PID)..."
sudo kill "$PID" 2>/dev/null || true

# Wait a moment for the process to stop
sleep 1

# Check if process is still running
if ps -p "$PID" > /dev/null 2>&1; then
    echo "Process still running, forcing kill..."
    sudo kill -9 "$PID" 2>/dev/null || true
    sleep 1
fi

# Clean up temporary directory
if [ -d "$TMP_DIR" ]; then
    echo "Cleaning up temporary files..."
    sudo rm -rf "$TMP_DIR"
    echo "Mock OAuth2 server stopped and cleaned up"
else
    echo "Mock OAuth2 server stopped"
fi

# Clean up certificate from system CA trust store if it exists
if [ -f /usr/local/share/ca-certificates/gcs-mock-oauth2.crt ]; then
    echo "Removing certificate from system CA trust store..."
    sudo rm -f /usr/local/share/ca-certificates/gcs-mock-oauth2.crt
    sudo update-ca-certificates 2>/dev/null || true
fi
