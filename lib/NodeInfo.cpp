#include "FNode.hpp"

const uint64_t NodeInfo::bytesToUint64(const char* bytes) {
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value = (value << 8) | bytes[i];
    }
    return value;
}

const uint64_t NodeInfo::genUUID() {
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
    
    uint64_t value = 0;
    const auto bytes = res.c_str();
    for (int i = 0; i < 8; i++) {
        value = (value << 8) | bytes[i];
    }
    return value;
}


NodeInfo::NodeInfo(const std::string& addr, const std::string& id)
    : addr(addr), id(id), ts(std::chrono::system_clock::now()) {}

NodeInfo::NodeInfo() {}