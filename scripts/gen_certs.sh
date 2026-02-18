#!/bin/bash
# Generate self-signed certificates for AegisEdge testing

mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -sha256 -days 3650 -nodes -subj "/C=US/ST=State/L=City/O=AegisEdge/OU=Security/CN=localhost"

echo "Certificates generated in certs/ folder."
echo "Update your .env with:"
echo "AEGISEDGE_SSL_CERT=certs/cert.pem"
echo "AEGISEDGE_SSL_KEY=certs/key.pem"
