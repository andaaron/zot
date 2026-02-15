#!/bin/bash
# Helper script to start the mock OAuth2 server for local testing
# This is needed because the distribution registry GCS driver creates an OAuth2 client
# that always tries to authenticate, even when using the emulator.
#
# Usage:
#   start-mock-oauth2.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common configuration
. "$SCRIPT_DIR/mock-oauth2-config.sh"

# Create temporary directory if it doesn't exist
mkdir -p "$TMP_DIR"

# Check if server is already running
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "Mock OAuth2 server is already running (PID: $PID)"
        exit 0
    else
        rm -f "$PID_FILE"
    fi
fi

# Generate self-signed certificate if it doesn't exist
# The certificate must be valid for all Google API domains we redirect to localhost
if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "Generating self-signed certificate for mock OAuth2 server..."
    openssl req -x509 -newkey rsa:2048 -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -days 365 -nodes -subj "/CN=oauth2.googleapis.com" \
        -addext "subjectAltName=DNS:oauth2.googleapis.com,DNS:www.googleapis.com,DNS:storage.googleapis.com" 2>/dev/null
    chmod 600 "$KEY_FILE"
    
    # Add certificate to system CA trust store so Go's HTTP client will trust it
    # This is needed because the OAuth2 client verifies TLS certificates
    echo "Adding certificate to system CA trust store..."
    if [ -d /usr/local/share/ca-certificates ]; then
        # Debian/Ubuntu
        sudo cp "$CERT_FILE" /usr/local/share/ca-certificates/gcs-mock-oauth2.crt 2>/dev/null && \
        sudo update-ca-certificates 2>/dev/null || echo "  (Failed to add to system trust store, but continuing...)"
    else
        echo "  WARNING: Could not find system CA trust store directory."
        echo "  The OAuth2 client may reject the self-signed certificate."
        echo "  You may need to manually add $CERT_FILE to your system's CA trust store."
    fi
fi

# Build the mock OAuth2 server
echo "Building mock OAuth2 server..."
cd "$SCRIPT_DIR"
go build -o "$SERVER_BINARY" mock-oauth2-server.go

# Check if oauth2.googleapis.com is in /etc/hosts
# Note: /etc/hosts modifications should be done by the caller (e.g., GitHub Actions)
if ! grep -q "oauth2.googleapis.com" /etc/hosts 2>/dev/null; then
    echo "ERROR: oauth2.googleapis.com is not in /etc/hosts"
    echo "Please add this line to /etc/hosts (requires sudo):"
    echo "  127.0.0.1 oauth2.googleapis.com"
    echo ""
    echo "This should be done by the setup script (e.g., GitHub Actions), not by this script."
    exit 1
fi

# Start the server (requires sudo for port 443)
echo "Starting mock OAuth2 server on port 443..."

# Use sudo if not running as root
if [ "$EUID" -eq 0 ]; then
    # Running as root, no need for sudo
    "$SERVER_BINARY" -cert "$CERT_FILE" -key "$KEY_FILE" -port 443 > "$LOG_FILE" 2>&1 &
    SERVER_PID=$!
    echo $SERVER_PID > "$PID_FILE"
else
    # Not root, use sudo -b to run in background (properly detached)
    sudo -b "$SERVER_BINARY" -cert "$CERT_FILE" -key "$KEY_FILE" -port 443 > "$LOG_FILE" 2>&1
    # Wait a moment for the process to start
    sleep 1
    # Find the PID of the running server process
    SERVER_PID=$(pgrep -f "mock-oauth2-server.*-cert.*$CERT_FILE" | head -1)
    if [ -z "$SERVER_PID" ]; then
        echo "ERROR: Could not find server process after starting"
        if [ -f "$LOG_FILE" ]; then
            echo "Last few lines of log:"
            tail -5 "$LOG_FILE" 2>/dev/null || echo "  (log file not readable)"
        fi
        exit 1
    fi
    echo $SERVER_PID > "$PID_FILE"
fi

# Wait a moment to check if the server started successfully
sleep 1
if ! ps -p $SERVER_PID > /dev/null 2>&1; then
    echo "ERROR: Server failed to start. Check the log file: $LOG_FILE"
    if [ -f "$LOG_FILE" ]; then
        echo "Last few lines of log:"
        tail -5 "$LOG_FILE" 2>/dev/null || echo "  (log file not readable)"
    fi
    rm -f "$PID_FILE"
    exit 1
fi

echo "Mock OAuth2 server started (PID: $SERVER_PID)"
echo "Log file: $LOG_FILE"
echo "Temporary files directory: $TMP_DIR"
echo ""
echo "To stop the server, run:"
echo "  test/gcs/stop-mock-oauth2.sh"
echo "  (This will stop the server and remove all temporary files including the log)"