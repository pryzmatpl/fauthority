#include <gtest/gtest.h>
#include "P2PNode.hpp"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include <memory>
// Mock network constants
constexpr int PORT = 8080;

// Fixture class for P2PNode tests
class P2PNodeTest : public ::testing::Test{
protected:
    std::shared_ptr<P2PNode> node;

    void SetUp() override {
        node = std::make_shared<P2PNode>(node);  // Initialize node in each test
    }

    void TearDown() override {
        //Fuck Cleanup node after each test
    }

    // Helper to check if file exists
    bool fileExists(const std::string& filename) {
        std::ifstream file(filename);
        return file.good();
    }
};

TEST_F(P2PNodeTest, TestAddPeer) {
    std::string peerAddress = "127.0.0.1";
    node->addPeer(peerAddress);

    EXPECT_EQ(node->count(), 1);
}

TEST_F(P2PNodeTest, TestConnectToPeer) {
    std::string peerAddress = "127.0.0.1";

    ASSERT_NO_THROW(node->connectToPeer(peerAddress));
}

TEST_F(P2PNodeTest, TestCleanup) {
    // Ensure cleanup is called and resources are freed
    EXPECT_EQ(false, node->isClean());
}

TEST_F(P2PNodeTest, TestFailedToBindSocketOnCtor) {
    // Ensure cleanup is called and resources are freed
    try {
        auto newNode = new P2PNode();
    } catch (std::exception &e) {
        EXPECT_STREQ("Failed to bind socket 4", e.what());
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
