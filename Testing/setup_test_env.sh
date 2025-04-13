#!/bin/bash

# Create test directories
mkdir -p /tmp/p2pca-test/certs
mkdir -p /tmp/p2pca-test/webroot
mkdir -p /tmp/p2pca-test/logs

# Generate self-signed root CA for testing
openssl req -x509 -nodes -new -sha256 -days 1024 -newkey rsa:2048 \
  -keyout /tmp/p2pca-test/certs/test-ca.key \
  -out /tmp/p2pca-test/certs/test-ca.pem \
  -subj "/C=US/ST=California/L=San Francisco/O=Test CA/CN=test-ca.example.com"

# Create test domain certificate request
openssl req -new -nodes -newkey rsa:2048 \
  -keyout /tmp/p2pca-test/certs/test-domain.key \
  -out /tmp/p2pca-test/certs/test-domain.csr \
  -subj "/C=US/ST=California/L=San Francisco/O=Test Domain/CN=test.example.com"

# Sign test domain certificate with our test CA
openssl x509 -req -sha256 -days 1024 \
  -in /tmp/p2pca-test/certs/test-domain.csr \
  -out /tmp/p2pca-test/certs/test-domain.crt \
  -CA /tmp/p2pca-test/certs/test-ca.pem \
  -CAkey /tmp/p2pca-test/certs/test-ca.key \
  -CAcreateserial

echo "Test environment setup complete at /tmp/p2pca-test/"
echo "Test CA certificate: /tmp/p2pca-test/certs/test-ca.pem"
echo "Test domain key: /tmp/p2pca-test/certs/test-domain.key"
echo "Test domain certificate: /tmp/p2pca-test/certs/test-domain.crt" 