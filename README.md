# Fauthority

Built in the open. A C++, p2p distributed cert authority.

![alt text](./docs/land.webp)

## To build
> Just run __build.sh__

#### Detailed:

First, run 

````
cppship build
````

Currently, you will run into an error regarding Openssl. Fix the ./build/CMakeLists.txt file by:
````
- target_link_libraries(fuckauthority_deps INTERFACE openssl::openssl)
+ target_link_libraries(fuckauthority_deps INTERFACE OpenSSL::SSL OpenSSL:Crypto)
````

Then, run

````
cd ./build && cmake ./
cmake --build ./
````

These commands are added to build.sh as in the README.md

## Design


## 9. Documentation on How to Run the P2P Certificate Authority Network

```markdown:docs/P2P_NETWORK_GUIDE.md
# P2P Certificate Authority Network Guide

This guide explains how to set up and operate a peer-to-peer certificate authority network using the provided tools.

## Overview

The P2P Certificate Authority system consists of two main components:

1. **p2pcert**: The command-line tool for requesting, managing, and installing certificates
2. **p2pcert-daemon**: The background service that participates in the P2P network

## Setting Up Network Nodes

### 1. Starting the First Node

To establish a new P2P certificate authority network, start the first node:

```bash

p2pcert-daemon start --node-id node1.example.com --addr 192.168.1.101

9. Documentation on How to Run the P2P Certificate Authority Network
bash
p2pcert-daemon start --node-id node1.example.com --addr 192.168.1.101
bash
On second machine
p2pcert-daemon start --node-id node2.example.com --addr 192.168.1.102
p2pcert-daemon connect 192.168.1.101:8443
On third machine
p2pcert-daemon start --node-id node3.example.com --addr 192.168.1.103
p2pcert-daemon connect 192.168.1.101:8443
bash
p2pcert-daemon status
p2pcert-daemon list
bash
p2pcert request example.com --validation http --webroot /var/www/html --p2p-node 192.168.1.101:8443
bash
p2pcert renew example.com --p2p-node 192.168.1.101:8443
bash
p2pcert install example.com --server-type nginx
This implementation provides a complete peer-to-peer certificate authority system with both client and daemon components. The daemon allows nodes to maintain connections with each other, form a consensus, and collectively provide certificate services.
The testing suite validates the functionality of both the standalone daemon and its integration with the certificate management client. The network protocol provides a foundation for inter-node communication, while the documentation offers guidance on deploying and operating the P2P network.


## Network Consensus

The P2P certificate authority requires a majority of nodes to agree before issuing a certificate. This protects against rogue certificate issuance.

By default, consensus requires:
- For networks with 3 or fewer nodes: All nodes must agree
- For networks with 4-6 nodes: At least 3 nodes must agree
- For networks with 7+ nodes: More than 2/3 of nodes must agree

## Security Considerations

1. **Node Authentication**: Each node must prove its identity to join the network using proof-of-work
2. **Network Security**: Use firewalls to restrict access to the P2P ports (8443 by default)
3. **Private Key Protection**: Each node's private key must be kept secure

## Troubleshooting

If you encounter issues with the P2P network:

1. Check connectivity between nodes:
   ```bash
   p2pcert-daemon connect 192.168.1.101:8443 --test
   ```
   # P2P Certificate Authority Network Guide

This guide explains how to set up and operate a peer-to-peer certificate authority network using the provided tools.

## Overview

The P2P Certificate Authority system consists of two main components:

1. **p2pcert**: The command-line tool for requesting, managing, and installing certificates
2. **p2pcert-daemon**: The background service that participates in the P2P network

## Setting Up Network Nodes

### 1. Starting the First Node

To establish a new P2P certificate authority network, start the first node:



### 3. Monitoring the Network

Check the status of your node and the overall network:

This creates a node that listens on the default port (8443) and identifies itself as 'node1.example.com'.

### 2. Adding More Nodes

On different machines, start additional nodes and connect them to the existing network:

## Using the P2P Network for Certificates

### 1. Requesting a Certificate

Request a new certificate using the P2P network:


### 3. Installing a Certificate

After obtaining a certificate, install it on your web server:

This connects to the P2P network through the specified node and submits the certificate request for consensus.

### 2. Renewing a Certificate

Renew an existing certificate through the P2P network:

2. Verify node status:
   ```bash
   p2pcert-daemon status
   ```

3. View logs:
   ```bash
   cat ~/.p2pca/logs/daemon.log
   ```

4. Restart a node:
   ```bash
   p2pcert-daemon stop
   p2pcert-daemon start
   ```