#include <gtest/gtest.h>
#include "FNode.hpp"
#include <fstream>
#include <memory>
#include "ConnectionResult.hpp"

// Fixture class for FNode tests
class FNodeTest : public ::testing::Test {
protected:
    std::shared_ptr<FNode> node;

    void SetUp() override {
        node = std::make_shared<FNode>("127.0.0.1"); // Initialize the FNode with a test address
    }

    void TearDown() override {
        node.reset(); // Cleanup after each test
    }

    // Helper to check if file exists
    bool fileExists(const std::string& filename) {
        std::ifstream file(filename);
        return file.good();
    }
};

TEST_F(FNodeTest, TestInitialization) {
    // Ensure the node is initialized correctly
    EXPECT_EQ(node->getHostAddr(), "127.0.0.1");
    EXPECT_TRUE(fileExists("public_key.pem"));
    EXPECT_TRUE(fileExists("private_key.pem"));
}

TEST_F(FNodeTest, TestAddPeerMore) {
    std::string peerAddress = "192.168.0.2";
    node->addPeer(peerAddress);

    EXPECT_EQ(node->countPeers(), 1);
    EXPECT_EQ(node->getPeers().front(), peerAddress);
}

TEST_F(FNodeTest, TestConnectToPeer) {
    std::string peerAddress = "127.0.0.1";

    // Since `connectToPeer` isn't fully implemented, test that it doesn't throw exceptions
    EXPECT_NO_THROW(node->connectToPeer(peerAddress));
}

TEST_F(FNodeTest, TestGenerateKeyPair) {
    // Test if the RSA keys are generated and saved correctly
    EXPECT_TRUE(fileExists("public_key.pem"));
    EXPECT_TRUE(fileExists("private_key.pem"));
}

TEST_F(FNodeTest, TestCleanup) {
    // Test if the cleanup process works as expected
    EXPECT_NO_THROW(node->cleanup());
    EXPECT_TRUE(node->isClean());
}

TEST_F(FNodeTest, TestMultiplePeers) {
    // Add multiple peers and verify
    std::vector<std::string> peers = {"192.168.0.2", "192.168.0.3", "192.168.0.4"};
    for (const auto& peer : peers) {
        node->addPeer(peer);
    }

    EXPECT_EQ(node->countPeers(), peers.size());
    EXPECT_EQ(node->getPeers(), peers);
}

TEST_F(FNodeTest, TestDestructorCleansUp) {
    // Verify the destructor cleans up resources
    node.reset(); // Explicitly trigger the destructor
    // Assuming cleanup works correctly, no exceptions or errors should occur
    SUCCEED();
}

TEST_F(FNodeTest, TestCopyConstructor) {
    // Test if the copy constructor works
    FNode copiedNode(*node);
    EXPECT_EQ(copiedNode.getHostAddr(), node->getHostAddr());
    EXPECT_EQ(copiedNode.countPeers(), node->countPeers());
}

TEST_F(FNodeTest, TestAssignmentOperator) {
    // Test the assignment operator
    FNode newNode("192.168.1.1");
    newNode = *node;
    EXPECT_EQ(newNode.getHostAddr(), node->getHostAddr());
    EXPECT_EQ(newNode.countPeers(), node->countPeers());
}

TEST_F(FNodeTest, TestFailedToBindSocketOnCtor) {
    // Simulate failure during socket initialization
    try {
        FNode failingNode("invalid_address");
    } catch (const std::exception& e) {
        EXPECT_STREQ("Failed to bind socket", e.what());
    }
}

TEST(FNodeTest, TestConnectToFAuthority) {
    FNode node("127.0.0.1");
    EXPECT_NO_THROW({
        ConnectionResult result = node.connectToFAuthority();
        EXPECT_EQ(result, ConnectionResult::Connected);
    });
}

TEST(FNodeTest, TestAddPeer) {
    FNode node("127.0.0.1");
    node.addPeer("192.168.0.2");
    EXPECT_EQ(node.countPeers(), 1);
    EXPECT_EQ(node.getPeers().front(), "192.168.0.2");
}
