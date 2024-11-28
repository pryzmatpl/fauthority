#ifndef P2P_NODEINFO_HPP
#define P2P_NODEINFO_HPP

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

using namespace std;
using namespace chrono;

struct NodeInfo {
        static const uint64_t bytesToUint64(const char* bytes);
        const uint64_t genUUID();
        string addr;
        string id;
        time_point<system_clock> ts;

        NodeInfo(const string& addr, const string& id);
        NodeInfo();
    };

#endif // F_NODEINFO_HPP
