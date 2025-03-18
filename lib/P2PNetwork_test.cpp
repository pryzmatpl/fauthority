#include <gtest/gtest.h>
#include "FNode.hpp"
#include "FServer.hpp"
#include "FSigner.hpp"
#include "SigningRequest.hpp"
#include "IncomingRequest.hpp"

class P2PNetworkTest : public ::testing::Test {
protected:
    FNode* node;
    FServer* server;
    FSigner* signer;

    void SetUp() override {
        node = new FNode("127.0.0.1");
        server = new FServer(*node);
        signer = new FSigner();
    }

    void TearDown() override {
        delete node;
        delete server;
        delete signer;
    }
};

TEST_F(P2PNetworkTest, TestNodeConnectionToAuthority) {
    EXPECT_EQ(node->connectToFAuthority(), ConnectionResult::Connected);
}

TEST_F(P2PNetworkTest, TestServerListening) {
    EXPECT_EQ(server->listenFAuth(), ListenerStatus::Listening);
}

TEST_F(P2PNetworkTest, TestServerAcceptingIncomingRequests) {
    auto requests = server->acceptIncoming();
    EXPECT_EQ(requests.size(), 1); // Expecting one dummy request
}

TEST_F(P2PNetworkTest, TestSigningCertificate) {
    createDummyPrivateKey(); // Ensure the private key is available
    SigningRequest request; // Create a dummy signing request
    EXPECT_EQ(signer->signCertificateFromRequest(request), SigningStatus::Signed);
    removeDummyPrivateKey(); // Clean up the dummy private key
}

TEST_F(P2PNetworkTest, TestServerRefresh) {
    EXPECT_TRUE(server->refresh());
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 