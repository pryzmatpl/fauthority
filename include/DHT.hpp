#ifndef DHT_HPP
#define DHT_HPP

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

class DHT {
public:
    struct NodeInfo {
        static const uint64_t bytesToUint64(const char* bytes);
        const uint64_t uuid();
        std::string _addr;
        uint64_t _id;
        std::chrono::time_point<std::chrono::system_clock> _ts;

        NodeInfo(const std::string& addr);
        NodeInfo();
    };

private:
    std::map<uint64_t, NodeInfo> _hosts;
    std::vector<uint64_t> _lookup;
    NodeInfo _currentNode;
    std::string ownAddress;

public:
    DHT();
    DHT(const std::string& address);

    bool addHost(const std::string& addr);

    bool removeNode(const std::string& removeNode);

    const std::string ownHost();

    int countLookups();

    int countHosts();
};

#endif // DHT_HPP
