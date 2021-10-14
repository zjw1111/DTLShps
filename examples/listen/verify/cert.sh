#!/bin/bash
mkdir -p cert
cd cert

# RootCA
openssl genrsa -out root.key
openssl req -new -x509 -key root.key  -days 3650 -set_serial 01 -out rootCA.crt -subj "/C=cn/ST=Beijing/L=Beijing/O=ChinaTelecom/OU=ctbri/CN=rootCA"

# CA
openssl genrsa -out ca.key
openssl req -new -key ca.key -out ca.csr -subj "/C=cn/ST=Beijing/L=Beijing/O=ChinaTelecom/OU=ctbri/CN=CA"
openssl x509 -req -in ca.csr -CA rootCA.crt -CAkey root.key -days 3650 -set_serial 02 -out CApure.crt -extfile v3.ext

# Client
openssl genrsa -out server.pem
openssl req -new -key server.pem -out server.csr -subj /C=cn/ST=Beijing/L=Beijing/O=ChinaTelecom/OU=ctbri/CN=Server
openssl x509 -req -in server.csr -CA CApure.crt -CAkey ca.key -days 3650 -set_serial 03 -out server.pub.crt -extfile v2.ext

# Server
openssl genrsa -out client.pem 
openssl req -new -key client.pem -out client.csr -subj /C=cn/ST=Beijing/L=Beijing/O=ChinaTelecom/OU=ctbri/CN=Client
openssl x509 -req -in client.csr -CA CApure.crt -CAkey ca.key -days 3650 -set_serial 04 -out client.pub.crt  -extfile v2.ext

cat CApure.crt rootCA.crt > CA.crt
rm -rf *.csr *.key CApure.crt rootCA.crt