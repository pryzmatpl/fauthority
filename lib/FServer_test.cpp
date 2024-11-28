#include <gtest/gtest.h>
#include "FServer.hpp"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#include <cstring>
#include <fstream>

// Fixture class for fserver tests
class FServerTest : public ::testing::Test{
protected:
    FServer* fserver;
    
    void SetUp() override { }

    void TearDown() override {
        delete fserver;  // Cleanup node after each test
    }
};

TEST_F(FServerTest, TestCreateLocal) {
    std::string peerAddress = "127.0.0.1";
    fserver = new FServer(peerAddress);

    EXPECT_EQ("127.0.0.1", fserver->ownHost());
}

TEST_F(FServerTest, TestLocalCreatedAndAddHost) {
    std::string peerAddress = "127.0.0.1";
    fserver = new FServer(peerAddress);
    fserver->addPeer("192.168.1.111");

    EXPECT_EQ(1, fserver->countHosts());
    EXPECT_EQ(1, fserver->countLookups());
}

TEST_F(FServerTest, TestLocalCreatedAndAddHosts) {
    std::string peerAddress = "127.0.0.1";
    fserver = new FServer(peerAddress);
    fserver->addPeer("192.168.1.111");
    fserver->addPeer("192.168.1.112");

    EXPECT_EQ(2, fserver->countHosts());
    EXPECT_EQ(2, fserver->countLookups());
}

TEST_F(FServerTest, TestLocalCreatedAndAddHostsAndRemove) {
    std::string peerAddress = "127.0.0.1";
    fserver = new FServer(peerAddress);
    fserver->addPeer("192.168.1.111");
    fserver->addPeer("192.168.1.112");
    
    auto res = fserver->removePeer("192.168.1.112");
    EXPECT_EQ(true, res);
    EXPECT_EQ(1, fserver->countHosts());
    EXPECT_EQ(1, fserver->countLookups());

    res = fserver->removePeer("192.168.1.111");
    EXPECT_EQ(true, res);
    EXPECT_EQ(0, fserver->countHosts());
    EXPECT_EQ(0, fserver->countLookups());
}

TEST_F(FServerTest, TestLocalRemovalOfEmpty) {
    std::string addr = "127.0.0.1";
    fserver = new FServer(addr);
    auto result = fserver->removePeer("192.168.1.111");

    EXPECT_EQ(0, fserver->countHosts());
    EXPECT_EQ(0, fserver->countLookups());
    EXPECT_EQ(false, result);
}

TEST_F(FServerTest, TestLocalCreateHostsAndReadAll) {
    std::string addr = "127.0.0.1";
    fserver = new FServer(addr);

    fserver->addPeer("192.168.1.111");
    fserver->addPeer("192.168.1.112");

    auto allHosts = fserver->getPeers();

    EXPECT_EQ(2, allHosts.size());

    auto it = std::find(allHosts.begin(), allHosts.end(), "192.168.1.112");
    EXPECT_TRUE(it != allHosts.end());

    it = std::find(allHosts.begin(), allHosts.end(), "192.168.1.111");
    EXPECT_FALSE(it == allHosts.end());
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
