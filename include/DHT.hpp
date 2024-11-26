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
#include "P2PNode.hpp"

using namespace std;
using namespace chrono;

class DHT {
public:
    struct NodeInfo {
        static const uint64_t bytesToUint64(const char* bytes);
        const uint64_t genUUID();
        string _addr;
        uint64_t _id;
        time_point<system_clock> _ts;

        NodeInfo(const string& addr);
        NodeInfo();
    };

private:
    map<uint64_t, NodeInfo> _hosts;
    vector<uint64_t> _lookup;
    NodeInfo _currentNode;
    string ownAddress;

public:
    DHT();
    DHT(const string& address);

    vector<P2PNode> discoverPeers();
    bool sendHostP2PNode(P2PNode &node);
    bool addPeer(const string& addr);

    vector<string> getPeers();

    bool removePeer(const string& removePeer);

    const string ownHost();

    int countLookups();

    int countHosts();
};

#endif // DHT_HPP
