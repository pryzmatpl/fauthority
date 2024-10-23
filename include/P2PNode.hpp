#ifndef P2P_NODE_HPP
#define P2P_NODE_HPP

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <string>

class P2PNode {
private:
    RSA* keyPair;
    int socketFd;
    std::vector<std::string> peers;
    const int PORT = 8080;
    
    void initializeOpenSSL();
    void generateKeyPair();
    void initializeNetwork();

public:
    P2PNode();
    void addPeer(const std::string& peerAddress);
    void connectToPeer(const std::string& peerAddress);
    void cleanup();
    ~P2PNode();
};

#endif // P2P_NODE_HPP
