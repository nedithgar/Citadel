#!/bin/bash

# Script to generate test SSH certificates for unit tests
# This creates a test CA and signs various types of certificates

set -e

# Create directory for test certificates
CERT_DIR="$(dirname "$0")"
cd "$CERT_DIR"

echo "Generating test certificates in: $CERT_DIR"

# Generate CA key pairs for each algorithm
echo "Generating CA keys..."

# Ed25519 CA
ssh-keygen -t ed25519 -f ca_ed25519 -N "" -C "Test Ed25519 CA" >/dev/null 2>&1

# ECDSA CAs
ssh-keygen -t ecdsa -b 256 -f ca_ecdsa_p256 -N "" -C "Test ECDSA P256 CA" >/dev/null 2>&1
ssh-keygen -t ecdsa -b 384 -f ca_ecdsa_p384 -N "" -C "Test ECDSA P384 CA" >/dev/null 2>&1
ssh-keygen -t ecdsa -b 521 -f ca_ecdsa_p521 -N "" -C "Test ECDSA P521 CA" >/dev/null 2>&1

# RSA CA
ssh-keygen -t rsa -b 2048 -f ca_rsa -N "" -C "Test RSA CA" >/dev/null 2>&1

echo "Generating user keys and certificates..."

# Generate Ed25519 user key and certificate
ssh-keygen -t ed25519 -f user_ed25519 -N "" -C "test@example.com" >/dev/null 2>&1
ssh-keygen -s ca_ed25519 -I "test-user-ed25519" -n testuser,alice -V +1h -z 1 user_ed25519.pub

# Generate ECDSA user keys and certificates
ssh-keygen -t ecdsa -b 256 -f user_ecdsa_p256 -N "" -C "test@example.com" >/dev/null 2>&1
ssh-keygen -s ca_ecdsa_p256 -I "test-user-p256" -n testuser -V +1h -z 2 user_ecdsa_p256.pub

ssh-keygen -t ecdsa -b 384 -f user_ecdsa_p384 -N "" -C "test@example.com" >/dev/null 2>&1
ssh-keygen -s ca_ecdsa_p384 -I "test-user-p384" -n testuser,admin -V +1h -z 3 user_ecdsa_p384.pub

ssh-keygen -t ecdsa -b 521 -f user_ecdsa_p521 -N "" -C "test@example.com" >/dev/null 2>&1
ssh-keygen -s ca_ecdsa_p521 -I "test-user-p521" -n testuser -V +1h -z 4 user_ecdsa_p521.pub

# Generate RSA user key and certificate
ssh-keygen -t rsa -b 2048 -f user_rsa -N "" -C "test@example.com" >/dev/null 2>&1
ssh-keygen -s ca_rsa -I "test-user-rsa" -n testuser -V +1h -z 5 user_rsa.pub

echo "Generating host certificates..."

# Generate host key and certificate
ssh-keygen -t ed25519 -f host_ed25519 -N "" -C "host.example.com" >/dev/null 2>&1
ssh-keygen -s ca_ed25519 -I "test-host" -h -n "*.example.com,example.com" -V +1h -z 100 host_ed25519.pub

echo "Generating certificates with special conditions..."

# Expired certificate
ssh-keygen -t ed25519 -f user_expired -N "" -C "expired@example.com" >/dev/null 2>&1
ssh-keygen -s ca_ed25519 -I "expired-cert" -n testuser -V -1d:-1h -z 200 user_expired.pub

# Not yet valid certificate
ssh-keygen -t ed25519 -f user_not_yet_valid -N "" -C "future@example.com" >/dev/null 2>&1
ssh-keygen -s ca_ed25519 -I "future-cert" -n testuser -V +1d:+2d -z 201 user_not_yet_valid.pub

# Certificate with critical options
ssh-keygen -t ed25519 -f user_critical_options -N "" -C "restricted@example.com" >/dev/null 2>&1
ssh-keygen -s ca_ed25519 -I "restricted-cert" -n testuser -O force-command="/bin/date" -O source-address="192.168.1.0/24,10.0.0.1" -V +1h -z 202 user_critical_options.pub

# Certificate with limited principals
ssh-keygen -t ed25519 -f user_limited_principals -N "" -C "limited@example.com" >/dev/null 2>&1
ssh-keygen -s ca_ed25519 -I "limited-cert" -n alice,bob -V +1h -z 203 user_limited_principals.pub

# Certificate with all extensions
ssh-keygen -t ed25519 -f user_all_extensions -N "" -C "full@example.com" >/dev/null 2>&1
ssh-keygen -s ca_ed25519 -I "full-cert" -n testuser -O permit-X11-forwarding -O permit-agent-forwarding -O permit-port-forwarding -O permit-pty -O permit-user-rc -V +1h -z 204 user_all_extensions.pub

# Clean up public key files we don't need
rm -f ca_*.pub

echo "Test certificates generated successfully!"
echo ""
echo "Generated files:"
ls -la *.pub *.key 2>/dev/null || true
ls -la *-cert.pub 2>/dev/null || true