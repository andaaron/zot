# Mock OAuth2 Server for GCS Testing

This directory contains a mock OAuth2 server that is used during GCS testing to handle OAuth2 token requests from the distribution registry GCS driver.

## Problem

The distribution registry GCS driver (`github.com/distribution/distribution/v3/registry/storage/driver/gcs`) creates an OAuth2 client that always tries to authenticate with Google's OAuth2 servers, even when using the storage-testbench emulator with `STORAGE_EMULATOR_HOST` set.

The driver hardcodes:
- `www.googleapis.com` for resumable uploads (in `newSession()`)
- `oauth2.googleapis.com` for OAuth2 token requests (via the OAuth2 client)

## Solution

This mock OAuth2 server:
1. Listens on HTTPS port 443 (requires root/sudo)
2. Returns a dummy OAuth2 token when POST `/token` is called
3. Uses a self-signed certificate for `oauth2.googleapis.com`

The setup action:
1. Redirects `oauth2.googleapis.com` to `127.0.0.1` via `/etc/hosts`
2. Builds and starts the mock OAuth2 server (which generates a self-signed certificate if needed)

The start script:
1. Checks if the server is already running
2. Generates a self-signed certificate if it doesn't exist
3. Builds the Go server binary
4. Verifies `/etc/hosts` is configured (errors if not)
5. Starts the server on port 443

## Files

- `test/gcs/mock-oauth2-server.go` - Go implementation of the mock OAuth2 server
- `test/gcs/mock-oauth2-config.sh` - Common configuration file with shared variables
- `test/gcs/start-mock-oauth2.sh` - Helper script to start the mock OAuth2 server
- `test/gcs/stop-mock-oauth2.sh` - Helper script to stop the mock OAuth2 server
- `.github/actions/setup-fake-gcs/action.yaml` - GitHub Actions setup that includes the mock server
- `.github/actions/teardown-fake-gcs/action.yaml` - GitHub Actions teardown that stops the mock server

## Local Testing

1. Add to `/etc/hosts` (requires sudo):
   ```
   127.0.0.1 oauth2.googleapis.com
   ```

2. Start the mock OAuth2 server:
   ```bash
   test/gcs/start-mock-oauth2.sh
   ```
   
   The script will:
   - Check if the server is already running
   - Generate a self-signed certificate if needed
   - Build the server binary
   - Start the server on port 443
   - Display the PID and log file location

3. Stop the mock OAuth2 server:
   ```bash
   test/gcs/stop-mock-oauth2.sh
   ```
   
   This will:
   - Stop the server process
   - Clean up all temporary files in `/tmp/gcs-mock-oauth2/`

## Configuration

All scripts share common configuration variables defined in `mock-oauth2-config.sh`:
- `TMP_DIR` - Temporary directory for all files (`/tmp/gcs-mock-oauth2`)
- `CERT_FILE` - Self-signed certificate file
- `KEY_FILE` - Private key file
- `PID_FILE` - Process ID file
- `LOG_FILE` - Server log file
- `SERVER_BINARY` - Compiled server binary

## GitHub Actions

The mock OAuth2 server is automatically started by the `setup-fake-gcs` action and stopped by the `teardown-fake-gcs` action. No manual intervention is needed.
