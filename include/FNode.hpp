#ifndef FNODE_HPP
#define FNODE_HPP

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
#include <map>
#include <vector>
#include <functional>
#include <cstdint>
#include <algorithm>
#include <memory>
#include <chrono>
#include <random>
#include <iostream>
#include <unordered_map>
#include "NodeInfo.hpp"
#include "ConnectionResult.hpp"
using namespace chrono;

using namespace std;

class FNode {
private:
    NodeInfo address;

    RSA* keyPair;
    int socketFd;
    std::vector<std::string> peers;
    
    void initializeOpenSSL();
    void generateKeyPair();
    void initializeNetwork();

public:
    FNode(string addr);
    FNode(FNode const&);
    FNode& operator=(FNode const&);
    void addPeer(const std::string& peerAddress);
    void connectToPeer(const std::string& peerAddress);
    vector<string> getPeers();
    string getHostAddr();
    bool cleanup();
    ConnectionResult connectToFAuthority();
    int countPeers();
    bool isClean();
    void disconnect();
    ~FNode();
};

#endif // FNODE_HPP
