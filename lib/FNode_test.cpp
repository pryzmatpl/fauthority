#include <gtest/gtest.h>
#include "FNode.hpp"
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
class FNodeTest : public ::testing::Test{
protected:
    std::shared_ptr<FNode> node;

    void SetUp() override {
        node = std::make_shared<FNode>();  // Initialize node in each test        
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

TEST_F(FNodeTest, TestAddPeer) {
    std::string peerAddress = "127.0.0.1";
    node->addPeer(peerAddress);

    EXPECT_EQ(node->count(), 1);
}

TEST_F(FNodeTest, TestConnectToPeer) {
    std::string peerAddress = "127.0.0.1";

    ASSERT_NO_THROW(node->connectToPeer(peerAddress));
}

TEST_F(FNodeTest, TestCleanup) {
    // Ensure cleanup is called and resources are freed
    EXPECT_EQ(false, node->isClean());
}

// TEST_F(FNodeTest, TestFailedToBindSocketOnCtor) {
//     // Ensure cleanup is called and resources are freed
//     try {
//         auto newNode = new FNode();
//     } catch (std::exception &e) {
//         EXPECT_STREQ("Failed to bind socket 4", e.what());
//     }
// }

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
