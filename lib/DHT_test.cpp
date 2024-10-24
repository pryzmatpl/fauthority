#include <gtest/gtest.h>
#include "DHT.hpp"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#include <cstring>
#include <fstream>

// Fixture class for DHT tests
class DHTTest : public ::testing::Test{
protected:
    DHT* dht;
    
    void SetUp() override { }

    void TearDown() override {
        delete dht;  // Cleanup node after each test
    }
};

TEST_F(DHTTest, TestCreateLocal) {
    std::string peerAddress = "127.0.0.1";
    dht = new DHT(peerAddress);

    EXPECT_EQ("127.0.0.1", dht->ownHost());
}

TEST_F(DHTTest, TestLocalCreatedAndAddHost) {
    std::string peerAddress = "127.0.0.1";
    dht = new DHT(peerAddress);
    dht->addHost("192.168.1.111");

    EXPECT_EQ(1, dht->countHosts());
    EXPECT_EQ(1, dht->countLookups());
}

TEST_F(DHTTest, TestLocalCreatedAndAddHosts) {
    std::string peerAddress = "127.0.0.1";
    dht = new DHT(peerAddress);
    dht->addHost("192.168.1.111");
    dht->addHost("192.168.1.112");

    EXPECT_EQ(2, dht->countHosts());
    EXPECT_EQ(2, dht->countLookups());
}

TEST_F(DHTTest, TestLocalCreatedAndAddHostsAndRemove) {
    std::string peerAddress = "127.0.0.1";
    dht = new DHT(peerAddress);
    dht->addHost("192.168.1.111");
    dht->addHost("192.168.1.112");
    
    dht->removeNode("192.168.1.112");

    EXPECT_EQ(1, dht->countHosts());
    EXPECT_EQ(1, dht->countLookups());
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
