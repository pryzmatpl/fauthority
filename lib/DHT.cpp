#include "DHT.hpp"

const uint64_t DHT::NodeInfo::bytesToUint64(const char* bytes) {
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

const uint64_t DHT::NodeInfo::uuid() {
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

    std::cout << "HASH: " << res.c_str() << "\n";

    return bytesToUint64(res.c_str());
}

DHT::NodeInfo::NodeInfo(const std::string& addr)
    : _addr(addr), _id(uuid()), _ts(std::chrono::system_clock::now()) {}

DHT::DHT(const std::string& address)
    : ownAddress(address), _currentNode(NodeInfo(address)) {}

bool DHT::addHost(const std::string& addr) {
    NodeInfo info(addr);
    _lookup.push_back(info._id);
    _hosts.emplace(info._id, std::move(info));
    
    return true;
}

bool DHT::removeNode(const NodeInfo& removeNode) {
    _hosts.erase(removeNode._id);

    auto it = std::remove(_lookup.begin(), _lookup.end(), removeNode._id);
    _lookup.erase(it, _lookup.end());
    return true;
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