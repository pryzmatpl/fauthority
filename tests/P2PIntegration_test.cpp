#include <gtest/gtest.h>
#include "P2PCertDaemonCli.hpp"
#include "P2PCertCLI.hpp"
#include <thread>
#include <chrono>
#include <iostream>
#include <filesystem>

class P2PIntegrationTest : public ::testing::Test {
protected:
    P2PCertDaemonCli* daemon1;
    P2PCertDaemonCli* daemon2;
    P2PCertCLI* certCli;
    
    void SetUp() override {
        // Set up test environment
        std::filesystem::create_directories("/tmp/p2pca-test");
        std::filesystem::create_directories("/tmp/p2pca-test/webroot");
        
        // Set HOME environment variable to the test directory
        setenv("HOME", "/tmp/p2pca-test", 1);
        
        // Create daemon instances
        daemon1 = new P2PCertDaemonCli();
        daemon2 = new P2PCertDaemonCli();
        
        // Create cert client
        certCli = new P2PCertCLI();
    }
    
    void TearDown() override {
        delete certCli;
        delete daemon2;
        delete daemon1;
        
        // Clean up test directory
        try {
            std::filesystem::remove_all("/tmp/p2pca-test");
        } catch (...) {
            // Ignore errors in cleanup
        }
    }
};

TEST_F(P2PIntegrationTest, TestNetworkCertificateIssuance) {
    // Start the daemon nodes
    const char* startArgs1[] = {
        "p2pcert-daemon",
        "start",
        "--node-id", "node1.example.com",
        "--addr", "127.0.0.1",
        "--port", "8444"
    };
    daemon1->run(8, const_cast<char**>(startArgs1));
    
    const char* startArgs2[] = {
        "p2pcert-daemon",
        "start",
        "--node-id", "node2.example.com",
        "--addr", "127.0.0.1",
        "--port", "8445"
    };
    daemon2->run(8, const_cast<char**>(startArgs2));
    
    // Allow some time for the daemons to start
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Connect the nodes
    const char* connectArgs[] = {
        "p2pcert-daemon",
        "connect",
        "127.0.0.1:8445"
    };
    daemon1->run(3, const_cast<char**>(connectArgs));
    
    // Allow some time for node connection
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Request a certificate using the client
    const char* requestArgs[] = {
        "p2pcert",
        "request",
        "test.example.com",
        "--validation", "http",
        "--webroot", "/tmp/p2pca-test/webroot",
        "--p2p-node", "127.0.0.1:8444"
    };
    int result = certCli->run(8, const_cast<char**>(requestArgs));
    EXPECT_EQ(result, 0);
    
    // Verify certificate existence
    const char* listArgs[] = {
        "p2pcert",
        "list"
    };
    result = certCli->run(2, const_cast<char**>(listArgs));
    EXPECT_EQ(result, 0);
    
    // Stop both daemons
    const char* stopArgs[] = {
        "p2pcert-daemon",
        "stop"
    };
    daemon1->run(2, const_cast<char**>(stopArgs));
    daemon2->run(2, const_cast<char**>(stopArgs));
}

TEST_F(P2PIntegrationTest, TestNetworkCertificateRenewal) {
    // Start the daemon nodes
    const char* startArgs1[] = {
        "p2pcert-daemon",
        "start",
        "--node-id", "node1.example.com",
        "--addr", "127.0.0.1",
        "--port", "8444"
    };
    daemon1->run(8, const_cast<char**>(startArgs1));
    
    const char* startArgs2[] = {
        "p2pcert-daemon",
        "start",
        "--node-id", "node2.example.com",
        "--addr", "127.0.0.1",
        "--port", "8445"
    };
    daemon2->run(8, const_cast<char**>(startArgs2));
    
    // Allow some time for the daemons to start
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Connect the nodes
    const char* connectArgs[] = {
        "p2pcert-daemon",
        "connect",
        "127.0.0.1:8445"
    };
    daemon1->run(3, const_cast<char**>(connectArgs));
    
    // Allow some time for node connection
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // First request a certificate
    const char* requestArgs[] = {
        "p2pcert",
        "request",
        "renew.example.com",
        "--validation", "http",
        "--webroot", "/tmp/p2pca-test/webroot",
        "--p2p-node", "127.0.0.1:8444"
    };
    certCli->run(8, const_cast<char**>(requestArgs));
    
    // Then test renewal
    const char* renewArgs[] = {
        "p2pcert",
        "renew",
        "renew.example.com",
        "--p2p-node", "127.0.0.1:8444"
    };
    int result = certCli->run(5, const_cast<char**>(renewArgs));
    EXPECT_EQ(result, 0);
    
    // Stop both daemons
    const char* stopArgs[] = {
        "p2pcert-daemon",
        "stop"
    };
    daemon1->run(2, const_cast<char**>(stopArgs));
    daemon2->run(2, const_cast<char**>(stopArgs));
}

TEST_F(P2PIntegrationTest, TestCompleteCertificateLifecycle) {
    // Start a small network of 3 nodes
    const char* startArgs1[] = {
        "p2pcert-daemon",
        "start",
        "--node-id", "node1.example.com",
        "--addr", "127.0.0.1",
        "--port", "8444"
    };
    daemon1->run(8, const_cast<char**>(startArgs1));
    
    const char* startArgs2[] = {
        "p2pcert-daemon",
        "start",
        "--node-id", "node2.example.com",
        "--addr", "127.0.0.1",
        "--port", "8445"
    };
    daemon2->run(8, const_cast<char**>(startArgs2));
    
    // Create a third daemon just for this test
    P2PCertDaemonCli daemon3;
    const char* startArgs3[] = {
        "p2pcert-daemon",
        "start",
        "--node-id", "node3.example.com",
        "--addr", "127.0.0.1",
        "--port", "8446"
    };
    daemon3.run(8, const_cast<char**>(startArgs3));
    
    // Allow some time for the daemons to start
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Connect all nodes to form a network
    const char* connectArgs1[] = {
        "p2pcert-daemon",
        "connect",
        "127.0.0.1:8445"
    };
    daemon1->run(3, const_cast<char**>(connectArgs1));
    
    const char* connectArgs2[] = {
        "p2pcert-daemon",
        "connect",
        "127.0.0.1:8446"
    };
    daemon1->run(3, const_cast<char**>(connectArgs2));
    
    const char* connectArgs3[] = {
        "p2pcert-daemon",
        "connect",
        "127.0.0.1:8444"
    };
    daemon2->run(3, const_cast<char**>(connectArgs3));
    
    // Allow some time for node connections
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // 1. Request a certificate
    const char* requestArgs[] = {
        "p2pcert",
        "request",
        "lifecycle.example.com",
        "--validation", "http",
        "--webroot", "/tmp/p2pca-test/webroot",
        "--p2p-node", "127.0.0.1:8444"
    };
    int result = certCli->run(8, const_cast<char**>(requestArgs));
    EXPECT_EQ(result, 0);
    
    // 2. Verify the certificate exists
    const char* listArgs[] = {
        "p2pcert",
        "list"
    };
    result = certCli->run(2, const_cast<char**>(listArgs));
    EXPECT_EQ(result, 0);
    
    // 3. Renew the certificate
    const char* renewArgs[] = {
        "p2pcert",
        "renew",
        "lifecycle.example.com",
        "--p2p-node", "127.0.0.1:8444"
    };
    result = certCli->run(5, const_cast<char**>(renewArgs));
    EXPECT_EQ(result, 0);
    
    // 4. Install the certificate for a web server
    const char* installArgs[] = {
        "p2pcert",
        "install",
        "lifecycle.example.com",
        "--server-type", "nginx"
    };
    result = certCli->run(5, const_cast<char**>(installArgs));
    EXPECT_EQ(result, 0);
    
    // 5. Revoke the certificate
    const char* revokeArgs[] = {
        "p2pcert",
        "revoke",
        "lifecycle.example.com",
        "--p2p-node", "127.0.0.1:8444",
        "--reason", "superseded"
    };
    result = certCli->run(7, const_cast<char**>(revokeArgs));
    EXPECT_EQ(result, 0);
    
    // Stop all daemons
    const char* stopArgs[] = {
        "p2pcert-daemon",
        "stop"
    };
    daemon1->run(2, const_cast<char**>(stopArgs));
    daemon2->run(2, const_cast<char**>(stopArgs));
    daemon3.run(2, const_cast<char**>(stopArgs));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 