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
    struct NodeInfo {
        static const uint64_t bytesToUint64(const char* bytes) {
            uint64_t value = 0;
            for (int i = 0; i < 8; i++) {
                value = (value << 8) | bytes[i];
            }
            return value;
        }
        
        const uint64_t uuid() {
            static std::random_device randomDev;
            static std::mt19937 randomNumGen(randomDev());
            std::uniform_int_distribution<int> dist(0, 15);

            const char *v = "0123456789abcdef";
            const bool dash[] = { 0, 0, 0, 0, true, 0, true, 0, true, 0, true, 0, 0, 0, 0, 0 };

            std::string res;
            for (int i = 0; i < 16; i++) {
                if (dash[i]) res += "-";
                res += v[dist(randomNumGen)];
                res += v[dist(randomNumGen)];
            }

            std::cout << "HASH:" << res.c_str() << "\n";

            return bytesToUint64(res.c_str());
        }

        std::string _addr;
        uint64_t _id;
        std::chrono::time_point<std::chrono::system_clock> _ts;

        NodeInfo(std::string addr) : 
            _addr(addr), _id(uuid()), _ts(std::chrono::system_clock::now()) {};
    }

    std::map<uint64_t, NodeInfo> _hosts;
    std::vector<uint64_t> _lookup;
    NodeInfo _currentNode;
    std::string ownAddress;

    public:
        DHT(const std::string& address) : ownAddress(address) {
            // Set current node information
            _currentNode = NodeInfo(ownAddress);
        }

        bool addHost(const std::string& addr) {
            auto info = NodeInfo(addr);
            _lookup.push_back(info._id);
            _hosts[info._id] = info;

            return true;
        }

        bool removeNode(const NodeInfo& removeNode) {            
            _hosts.erase(removeNode._id);
            std::remove(
                _lookup.begin(),
                _lookup.end(),
                removeNode
            );
            _lookup.erase(_lookup.end());

            return true;
        }

        const std::string ownHost() {
            return ownAddress;
        }

        int countLookups() {
            return _lookup.size();
        }

        int countHosts() {
            return _hosts.size();
        }
};

#endif