#include <gtest/gtest.h>
#include "NetworkConsensus.hpp"
#include "FNode.hpp"
#include "SigningRequest.hpp"

class NetworkConsensusTest : public ::testing::Test {
protected:
    FNode* node;
    NetworkConsensus* consensus;
    
    void SetUp() override {
        node = new FNode("127.0.0.1");
        consensus = new NetworkConsensus(node);
    }
    
    void TearDown() override {
        delete consensus;
        delete node;
    }
};

TEST_F(NetworkConsensusTest, TestNoPeers) {
    EXPECT_FALSE(consensus->hasMinimumPeers());
}

TEST_F(NetworkConsensusTest, TestWithPeers) {
    node->addPeer("192.168.1.1");
    // Force update of active peers in consensus
    consensus = new NetworkConsensus(node);
    EXPECT_TRUE(consensus->hasMinimumPeers());
}

TEST_F(NetworkConsensusTest, TestMinimumValidations) {
    // Test with 1 peer (total 2 nodes)
    node->addPeer("192.168.1.1");
    consensus = new NetworkConsensus(node);
    EXPECT_EQ(consensus->getMinimumValidationsRequired(), 1);
    
    // Test with 2 peers (total 3 nodes) - All nodes must agree
    node->addPeer("192.168.1.2");
    consensus = new NetworkConsensus(node);
    EXPECT_EQ(consensus->getMinimumValidationsRequired(), 2);
    
    // Test with 3 peers (total 4 nodes) - At least 3 nodes must agree
    node->addPeer("192.168.1.3");
    consensus = new NetworkConsensus(node);
    EXPECT_EQ(consensus->getMinimumValidationsRequired(), 3);
    
    // Test with 5 peers (total 6 nodes) - At least 3 nodes must agree
    node->addPeer("192.168.1.4");
    node->addPeer("192.168.1.5");
    consensus = new NetworkConsensus(node);
    EXPECT_EQ(consensus->getMinimumValidationsRequired(), 3);
    
    // Test with 7 peers (total 8 nodes) - More than 2/3 must agree
    node->addPeer("192.168.1.6");
    node->addPeer("192.168.1.7");
    consensus = new NetworkConsensus(node);
    EXPECT_EQ(consensus->getMinimumValidationsRequired(), 6); // 8 * 2/3 = 5.33, round up to 6
}

// Add a test for validateRequest with sufficient and insufficient peers
TEST_F(NetworkConsensusTest, TestValidateRequest) {
    // Mock SigningRequest
    Certificate cert;
    SigningRequest request;
    
    // Test with no peers - should be insufficient
    EXPECT_EQ(consensus->validateRequest(request), ConsensusResult::Insufficient);
    
    // Add a peer but can't test validation fully without mocking network communication
    node->addPeer("192.168.1.1");
    consensus = new NetworkConsensus(node);
    // Real validation would require mocking the network response
}

// Test that port configuration works correctly
TEST_F(NetworkConsensusTest, TestPortConfiguration) {
    int customPort = 8444;
    NetworkConsensus customConsensus(node, customPort);
    EXPECT_EQ(customConsensus.getPort(), customPort);
    
    // Test changing port
    customConsensus.setPort(8445);
    EXPECT_EQ(customConsensus.getPort(), 8445);
} 