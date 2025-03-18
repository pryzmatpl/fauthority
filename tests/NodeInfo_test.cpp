#include <gtest/gtest.h>
#include "NodeInfo.hpp"
#include <cstring>
#include <thread>

class NodeInfoTest : public ::testing::Test {
protected:
    void SetUp() override {
    }

    void TearDown() override {
    }
};

// Test: Default Constructor
TEST_F(NodeInfoTest, DefaultConstructor) {
    NodeInfo node;
    EXPECT_EQ(node.addr, ""); 
    EXPECT_EQ(node.id, "");   
    EXPECT_NO_THROW(auto time = node.ts);
}

// Test: Parameterized Constructor
TEST_F(NodeInfoTest, ParameterizedConstructor) {
    NodeInfo node("192.168.1.1", "unique-id");
    EXPECT_EQ(node.addr, "192.168.1.1");
    EXPECT_EQ(node.id, "unique-id");
    EXPECT_NO_THROW(auto time = node.ts);
}

// Test: bytesToUint64
TEST_F(NodeInfoTest, BytesToUint64) {
    const char testBytes[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint64_t result = NodeInfo::bytesToUint64(testBytes);

    uint64_t expected = 0x0102030405060708;
    EXPECT_EQ(result, expected);
}

// Test: genUUID (Basic functionality and uniqueness)
TEST_F(NodeInfoTest, GenerateUUID) {
    uint64_t uuid1 = NodeInfo::genUUID();
    uint64_t uuid2 = NodeInfo::genUUID();

    // UUID should not be zero
    EXPECT_NE(uuid1, 0);
    EXPECT_NE(uuid2, 0);

    // UUIDs should be unique
    EXPECT_NE(uuid1, uuid2);
}

// Test: genUUID (Statistical test for multiple UUIDs)
TEST_F(NodeInfoTest, GenerateMultipleUUIDs) {
    std::set<uint64_t> uuids;

    // Generate 100 UUIDs and ensure they are unique
    for (int i = 0; i < 100; i++) {
        uuids.insert(NodeInfo::genUUID());
    }

    EXPECT_EQ(uuids.size(), 100); // All UUIDs should be unique
}

// Test: Timestamp Accuracy
TEST_F(NodeInfoTest, TimestampTest) {
    NodeInfo node1;
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Small delay
    NodeInfo node2;

    // Ensure timestamps are not equal due to delay
    EXPECT_NE(node1.ts, node2.ts);
}
