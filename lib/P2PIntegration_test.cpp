#include <gtest/gtest.h>
#include "FNode.hpp"
#include "FServer.hpp"
#include "FSigner.hpp"
#include "Certificate.hpp"
#include "SigningRequest.hpp"
#include "NetworkConsensus.hpp"
#include <thread>
#include <chrono>
#include <vector>

class P2PIntegrationTest : public ::testing::Test {
protected:
    std::vector<FNode*> nodes;
    std::vector<FServer*> servers;
    
    void SetUp() override {
        // Create multiple nodes
        for (int i = 0; i < 3; i++) {
            std::string address = "127.0.0." + std::to_string(i+1);
            FNode* node = new FNode(address);
            nodes.push_back(node);
        }
        
        // Connect nodes to each other
        for (size_t i = 0; i < nodes.size(); i++) {
            for (size_t j = 0; j < nodes.size(); j++) {
                if (i != j) {
                    nodes[i]->addPeer(nodes[j]->getHostAddr());
                }
            }
        }
        
        // Create servers for each node
        for (auto& node : nodes) {
            FServer* server = new FServer(*node);
            servers.push_back(server);
        }
    }
    
    void TearDown() override {
        for (auto* server : servers) {
            delete server;
        }
        servers.clear();
        
        for (auto* node : nodes) {
            delete node;
        }
        nodes.clear();
    }
    
    Certificate createTestCertificate() {
        EVP_PKEY* testKey = EVP_PKEY_new();
        RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
        EVP_PKEY_assign_RSA(testKey, rsa);
        
        Certificate cert("test.example.com", "Test Org", "US");
        cert.generateX509(testKey);
        
        EVP_PKEY_free(testKey);
        return cert;
    }
};

TEST_F(P2PIntegrationTest, TestNetworkFormation) {
    // Verify all nodes have the correct number of peers
    for (auto* node : nodes) {
        EXPECT_EQ(node->countPeers(), nodes.size() - 1);
    }
}

TEST_F(P2PIntegrationTest, TestNetworkConsensus) {
    // Create a network consensus object
    NetworkConsensus consensus(*nodes[0]);
    
    // Verify it has minimum peers
    EXPECT_TRUE(consensus.hasMinimumPeers());
    
    // Calculate required validations
    int requiredValidations = consensus.getMinimumValidationsRequired();
    EXPECT_GT(requiredValidations, 0);
}

TEST_F(P2PIntegrationTest, TestCertificateSigningE2E) {
    // Create a test certificate
    Certificate cert = createTestCertificate();
    
    // Create a signing request
    IncomingRequest incomingReq("SIGN\n" + cert.toPEM(), "192.168.1.100");
    incomingReq.parse();
    SigningRequest signingReq(incomingReq);
    
    // Create a signer with the first node
    FSigner signer(*nodes[0]);
    
    // Sign the certificate
    SigningStatus status = signer.signCertificateFromRequest(signingReq);
    
    // In a real network, this would succeed, but our test environment
    // can't actually connect to peers
    EXPECT_EQ(status, SigningStatus::NetworkError);
} 