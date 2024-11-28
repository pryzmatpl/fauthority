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
#include "FNode.hpp"
#include "ListenerStatus.hpp"
#include "SigningRequest.hpp"
#include "IncomingRequest.hpp"

using namespace std;

class FServer {
public:
    
private:
    map<uint64_t, FNode> hosts;
    vector<uint64_t> lookup;    
    std::vector<std::string> peers; // List of peers
    int lookupCount = 0;            // Mock lookup counter
    string host;

public:
    FServer();
    FServer(const FNode& node);
    FServer(const string& address);

    ListenerStatus listenFAuth();
    vector<IncomingRequest> acceptIncoming();
    bool refresh();
    void shutdown();

    void initializeNetwork();
    
    std::string ownHost() const;
    void addPeer(const std::string& peerAddress);
    bool removePeer(const std::string& peerAddress);
    int countHosts() const;
    int countLookups() const;
    std::vector<std::string> getPeers() const;
};

#endif // DHT_HPP
