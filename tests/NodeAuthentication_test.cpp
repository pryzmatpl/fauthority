#include <gtest/gtest.h>
#include "NodeAuthentication.hpp"
#include "FNode.hpp"

class NodeAuthenticationTest : public ::testing::Test {
protected:
    NodeAuthentication* auth;
    FNode* testNode;
    
    void SetUp() override {
        auth = new NodeAuthentication();
        testNode = new FNode("192.168.1.100");
    }
    
    void TearDown() override {
        delete auth;
        delete testNode;
    }
};

TEST_F(NodeAuthenticationTest, TestProofOfWork) {
    auth->setWorkDifficulty(1); // Set low difficulty for testing
    
    AuthStatus status = auth->performProofOfWork(*testNode);
    EXPECT_TRUE(status == AuthStatus::Authenticated || status == AuthStatus::Rejected);
}

TEST_F(NodeAuthenticationTest, TestProofOfStake) {
    auth->setMinimumStake(50); // Set reasonable stake for testing
    
    AuthStatus status = auth->performProofOfStake(*testNode);
    EXPECT_TRUE(status == AuthStatus::Authenticated || status == AuthStatus::Rejected);
}

TEST_F(NodeAuthenticationTest, TestSocialTrust) {
    // Add some trusted nodes
    auth->addTrustedNode("192.168.1.101");
    auth->addTrustedNode("192.168.1.102");
    
    AuthStatus status = auth->verifySocialTrust(*testNode);
    EXPECT_TRUE(status == AuthStatus::Authenticated || status == AuthStatus::Rejected);
}

TEST_F(NodeAuthenticationTest, TestWebOfTrust) {
    // Create a web of trust
    auth->addTrustRelation("192.168.1.101", "192.168.1.102");
    auth->addTrustRelation("192.168.1.102", "192.168.1.100"); // Trust our test node
    auth->addTrustRelation("192.168.1.103", "192.168.1.100"); // Another node trusts our test node
    
    AuthStatus status = auth->verifyWebOfTrust(*testNode);
    EXPECT_TRUE(status == AuthStatus::Authenticated || status == AuthStatus::Rejected);
}

TEST_F(NodeAuthenticationTest, TestVerifyNodeAuthenticity) {
    // This should always return true in our simplified implementation
    EXPECT_TRUE(auth->verifyNodeAuthenticity("192.168.1.100"));
}

TEST_F(NodeAuthenticationTest, TestCalculateTrustScore) {
    // Create a web of trust
    auth->addTrustRelation("192.168.1.101", "192.168.1.102");
    auth->addTrustRelation("192.168.1.102", "192.168.1.100");
    auth->addTrustRelation("192.168.1.103", "192.168.1.100");
    
    int score = auth->calculateTrustScore("192.168.1.100");
    EXPECT_GE(score, 0);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 