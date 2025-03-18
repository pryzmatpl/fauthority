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
        consensus = new NetworkConsensus(*node);
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
    consensus = new NetworkConsensus(*node);
    EXPECT_TRUE(consensus->hasMinimumPeers());
}

TEST_F(NetworkConsensusTest, TestMinimumValidations) {
    // Test with 1 peer
    node->addPeer("192.168.1.1");
    consensus = new NetworkConsensus(*node);
    EXPECT_EQ(consensus->getMinimumValidationsRequired(), 1);
    
    // Test with 3 peers
    node->addPeer("192.168.1.2");
    node->addPeer("192.168.1.3");
    consensus = new NetworkConsensus(*node);
    EXPECT_EQ(consensus->getMinimumValidationsRequired(), 1);
    
    // Test with 5 peers
    node->addPeer("192.168.1.4");
    node->addPeer("192.168.1.5");
    consensus = new NetworkConsensus(*node);
    EXPECT_EQ(consensus->getMinimumValidationsRequired(), 2);
} 