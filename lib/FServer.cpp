#include "FServer.hpp"


FServer::FServer(const std::string& address)
    : ownAddress(address), _currentNode(NodeInfo(address)) {}

bool DHT::addPeer(const std::string& addr) {
    NodeInfo info(addr);
    _lookup.push_back(info._id);
    _hosts.emplace(info._id, std::move(info));
    
    return true;
}

std::vector<std::string> FServer::getPeers() {
    std::vector<std::string> peers;
    
    for (const auto& host : _hosts) {
        peers.push_back(host.second._addr);
    }

    return peers;
}

void FServer::initializeNetwork() {    
    // Create socket
    auto socketFd = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFd < 0) {
        throw std::runtime_error("Failed to create socket");
    }

    // Set socket options for reuse
    int opt = 1;
    setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Configure server address
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(55555);

    // Bind socket
    if (bind(socketFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        char* message;
        asprintf(&message, "Failed to bind socket %d", socketFd);
        throw std::runtime_error(message);
    }

    // Start listening
    if (listen(socketFd, 5) < 0) {
        throw std::runtime_error("Failed to listen on socket");
    }
}


bool FServer::removePeer(const std::string& removeNodeAddr) {
    for (auto beg = _lookup.begin(); beg != _lookup.end(); beg++) {
        if (_hosts[*beg]._addr == removeNodeAddr) {
            _hosts.erase(*beg);
            _lookup.erase(beg);

            return true;
        }
    }

    return false;
}

const std::string FServer::ownHost() {
    return ownAddress;
}

int FServer::countLookups() {
    return _lookup.size();
}

int FServer::countHosts() {
    return _hosts.size();
}

/** send out the keypair for current node **/
bool FServer::sendHostP2PNode(FNode &node)
{
    auto sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        throw std::runtime_error("Failed to create socket");
    }

    // Bind to port
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(6881);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        throw std::runtime_error("Failed to bind to port");
    }

    // Receive data
    char buffer[8];
    struct sockaddr_in senderAddr;
    socklen_t senderLen = sizeof(senderAddr);
    
    int received = recvfrom(sock, buffer, sizeof(buffer)-1, 0,
                            (struct sockaddr*)&senderAddr, &senderLen);
    
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            throw "Timeout";
        }
        throw "Error receiving";
    }

    if ("DISCOVER" == buffer) {
        auto buf = node.toBuffer();
        auto sz = sizeof(buf);
        write(sock, (const void*)buf, sz);
    }

    return true;
}

std::vector<FNode> FServer::discoverPeers()
{
    auto sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        throw std::runtime_error("Failed to create socket");
    }

    int broadcast = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
        close(sock);
        throw std::runtime_error("Failed to set broadcast option");
    }

        // Set receive timeout
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Bind to port
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(6881);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        throw std::runtime_error("Failed to bind to port");
    }

    // Receive data
    char buffer[1024];
    struct sockaddr_in senderAddr;
    socklen_t senderLen = sizeof(senderAddr);
    
    int received = recvfrom(sock, buffer, sizeof(buffer)-1, 0,
                            (struct sockaddr*)&senderAddr, &senderLen);
    
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            throw "Timeout";
        }
        throw "Error receiving";
    }

    buffer[received] = '\0';
    
    throw "Return";
}

ListenerStatus FServer::listen()
{
    return ListenerStatus::Unavailable
}