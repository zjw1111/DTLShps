#!/bin/bash
mkdir -p cert
cd cert

# CA
openssl genrsa -out ca.key
openssl req -new -x509 -key ca.key  -days 3650 -set_serial 01 -out CA.crt -subj /C=cn/ST=Beijing/L=Beijing/O=ChinaTelecom/OU=ctbri/CN=CA

# Client
openssl genrsa -out server.pem
openssl req -new -key server.pem -out server.csr -subj /C=cn/ST=Beijing/L=Beijing/O=ChinaTelecom/OU=ctbri/CN=Server
openssl x509 -req -in server.csr -CA CA.crt -CAkey ca.key -days 3650 -set_serial 03 -out server.pub.crt

# Server
openssl genrsa -out client.pem 
openssl req -new -key client.pem -out client.csr -subj /C=cn/ST=Beijing/L=Beijing/O=ChinaTelecom/OU=ctbri/CN=Client
openssl x509 -req -in client.csr -CA CA.crt -CAkey ca.key -days 3650 -set_serial 04 -out client.pub.crt 

rm -rf *.csr ca.key