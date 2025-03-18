#include <gtest/gtest.h>
#include "FServer.hpp"
#include "FNode.hpp"
#include "IncomingRequest.hpp"
#include <thread>
#include <chrono>

class FServerTest : public ::testing::Test {
protected:
    FNode* node;
    FServer* server;

    void SetUp() override {
        node = new FNode("127.0.0.1");
        server = new FServer(*node);
    }

    void TearDown() override {
        delete server;
        delete node;
    }
};

TEST_F(FServerTest, TestCreateLocalServer) {
    EXPECT_NO_THROW(FServer(*node));
}

TEST_F(FServerTest, TestServerListening) {
    EXPECT_EQ(server->listenFAuth(), ListenerStatus::Listening);
}

TEST_F(FServerTest, TestServerAcceptingIncomingRequests) {
    // Start a thread to simulate an incoming connection
    std::thread([this]() {
        // Simulate a client connecting to the server
        int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
        serverAddr.sin_port = htons(55555);
        connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        close(clientSocket);
    }).detach();

    // Allow some time for the connection to be established
    std::this_thread::sleep_for(std::chrono::seconds(1));

    auto requests = server->acceptIncoming();
    EXPECT_EQ(requests.size(), 1); // Expecting one dummy request
}

TEST_F(FServerTest, TestAddPeer) {
    std::string peerAddress = "192.168.1.1";
    server->addPeer(peerAddress);
    EXPECT_EQ(server->countHosts(), 1);
    EXPECT_EQ(server->getPeers().front(), peerAddress);
}

TEST_F(FServerTest, TestRemovePeer) {
    std::string peerAddress = "192.168.1.1";
    server->addPeer(peerAddress);
    EXPECT_TRUE(server->removePeer(peerAddress));
    EXPECT_EQ(server->countHosts(), 0);
}

TEST_F(FServerTest, TestRefreshServer) {
    EXPECT_TRUE(server->refresh());
}

TEST_F(FServerTest, TestServerShutdown) {
    EXPECT_NO_THROW(server->shutdown());
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
