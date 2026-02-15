#!/bin/bash
# Common configuration for mock OAuth2 server scripts
# This file should be sourced by start-mock-oauth2.sh and stop-mock-oauth2.sh

# Temporary directory for all mock OAuth2 server files
TMP_DIR="/tmp/gcs-mock-oauth2"

# File paths within the temporary directory
CERT_FILE="$TMP_DIR/oauth2-cert.pem"
KEY_FILE="$TMP_DIR/oauth2-key.pem"
PID_FILE="$TMP_DIR/mock-oauth2.pid"
LOG_FILE="$TMP_DIR/mock-oauth2.log"
SERVER_BINARY="$TMP_DIR/mock-oauth2-server"
