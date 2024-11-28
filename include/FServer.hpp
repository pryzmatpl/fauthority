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

public:
    FServer();
    FServer(const FNode& node);
    FServer(const string& address);

    ListenerStatus listen();
    vector<IncomingRequest> acceptIncoming();
    bool refresh();
    void shutdown();

    void FServer::initializeNetwork();
    
};

#endif // DHT_HPP
