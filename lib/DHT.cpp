#include "DHT.hpp"

const uint64_t DHT::NodeInfo::bytesToUint64(const char* bytes) {
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

const uint64_t DHT::NodeInfo::genUUID() {
    static std::random_device randomDev;
    static std::mt19937 randomNumGen(randomDev());
    std::uniform_int_distribution<int> dist(0, 15);

    const char* v = "0123456789abcdef";
    const bool dash[] = {0, 0, 0, 0, true, 0, true, 0, true, 0, true, 0, 0, 0, 0, 0};

    std::string res;
    for (int i = 0; i < 16; i++) {
        if (dash[i]) res += "-";
        res += v[dist(randomNumGen)];
        res += v[dist(randomNumGen)];
    }    

    return bytesToUint64(res.c_str());
}

DHT::NodeInfo::NodeInfo(const std::string& addr)
    : _addr(addr), _id(genUUID()), _ts(std::chrono::system_clock::now()) {}

DHT::NodeInfo::NodeInfo() {}

DHT::DHT(const std::string& address)
    : ownAddress(address), _currentNode(NodeInfo(address)) {}

bool DHT::addPeer(const std::string& addr) {
    NodeInfo info(addr);
    _lookup.push_back(info._id);
    _hosts.emplace(info._id, std::move(info));
    
    return true;
}

std::vector<std::string> DHT::getPeers() {
    std::vector<std::string> peers;
    
    for (const auto& host : _hosts) {
        peers.push_back(host.second._addr);
    }

    return peers;
}

bool DHT::removePeer(const std::string& removeNodeAddr) {
    for (auto beg = _lookup.begin(); beg != _lookup.end(); beg++) {
        if (_hosts[*beg]._addr == removeNodeAddr) {
            _hosts.erase(*beg);
            _lookup.erase(beg);

            return true;
        }
    }

    return false;
}

const std::string DHT::ownHost() {
    return ownAddress;
}

int DHT::countLookups() {
    return _lookup.size();
}

int DHT::countHosts() {
    return _hosts.size();
}

/** send out the keypair for current node **/
bool sendHostP2PNode(P2PNode &node)
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

std::vector<P2PNode> DHT::discoverPeers()
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