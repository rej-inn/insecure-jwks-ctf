#!/bin/bash
set -e

mkdir -p keys

echo "[*] Generating strong RSA keys..."
openssl genrsa -out keys/strong_rsa_1.pem 2048
openssl rsa -in keys/strong_rsa_1.pem -pubout -out keys/strong_rsa_1.pub

openssl genrsa -out keys/strong_rsa_2.pem 2048
openssl rsa -in keys/strong_rsa_2.pem -pubout -out keys/strong_rsa_2.pub

echo "[*] Generating weak RSA key (CTF)..."
openssl genrsa -out keys/small_rsa.pem 512
openssl rsa -in keys/small_rsa.pem -pubout -out keys/small_rsa.pub

echo "[+] Key generation complete"
