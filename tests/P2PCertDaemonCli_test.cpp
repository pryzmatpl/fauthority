#include <gtest/gtest.h>
#include "P2PCertDaemonCli.hpp"
#include <thread>
#include <chrono>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <filesystem>

class P2PCertDaemonCliTest : public ::testing::Test {
protected:
    P2PCertDaemonCli* daemon;
    std::string testConfigPath;
    std::string testNodesPath;
    
    void SetUp() override {
        // Set up a test config directory
        testConfigPath = "/tmp/p2pca-test/config.json";
        testNodesPath = "/tmp/p2pca-test/nodes.txt";
        
        // Create test directory
        std::filesystem::create_directories("/tmp/p2pca-test");
        
        // Create a simple test nodes file
        std::ofstream nodesFile(testNodesPath);
        nodesFile << "192.168.1.10:8443" << std::endl;
        nodesFile << "192.168.1.11:8443" << std::endl;
        nodesFile.close();
        
        // Set HOME environment variable to the test directory
        setenv("HOME", "/tmp/p2pca-test", 1);
        
        daemon = new P2PCertDaemonCli();
    }
    
    void TearDown() override {
        delete daemon;
        
        // Clean up test directory
        try {
            std::filesystem::remove_all("/tmp/p2pca-test");
        } catch (...) {
            // Ignore errors in cleanup
        }
    }
};

TEST_F(P2PCertDaemonCliTest, TestStartStopDaemon) {
    // Start the daemon with test parameters
    const char* startArgs[] = {
        "p2pcert-daemon",
        "start",
        "--node-id", "test-node.example.com",
        "--addr", "127.0.0.1",
        "--port", "8444"
    };
    int result = daemon->run(8, const_cast<char**>(startArgs));
    EXPECT_EQ(result, 0);
    
    // Small delay to allow threads to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Check status
    const char* statusArgs[] = {
        "p2pcert-daemon",
        "status"
    };
    result = daemon->run(2, const_cast<char**>(statusArgs));
    EXPECT_EQ(result, 0);
    
    // Stop the daemon
    const char* stopArgs[] = {
        "p2pcert-daemon",
        "stop"
    };
    result = daemon->run(2, const_cast<char**>(stopArgs));
    EXPECT_EQ(result, 0);
}

TEST_F(P2PCertDaemonCliTest, TestNodeConnect) {
    // Start the daemon first
    const char* startArgs[] = {
        "p2pcert-daemon",
        "start",
        "--node-id", "test-node.example.com",
        "--addr", "127.0.0.1",
        "--port", "8444"
    };
    daemon->run(8, const_cast<char**>(startArgs));
    
    // Small delay to allow threads to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Connect to another node
    const char* connectArgs[] = {
        "p2pcert-daemon",
        "connect",
        "192.168.1.12:8443"
    };
    int result = daemon->run(3, const_cast<char**>(connectArgs));
    EXPECT_EQ(result, 0);
    
    // List connected nodes
    const char* listArgs[] = {
        "p2pcert-daemon",
        "list"
    };
    result = daemon->run(2, const_cast<char**>(listArgs));
    EXPECT_EQ(result, 0);
    
    // Disconnect from the node
    const char* disconnectArgs[] = {
        "p2pcert-daemon",
        "disconnect",
        "192.168.1.12:8443"
    };
    result = daemon->run(3, const_cast<char**>(disconnectArgs));
    EXPECT_EQ(result, 0);
    
    // Stop the daemon
    const char* stopArgs[] = {
        "p2pcert-daemon",
        "stop"
    };
    daemon->run(2, const_cast<char**>(stopArgs));
}

TEST_F(P2PCertDaemonCliTest, TestCertificateSigningRequest) {
    // Start the daemon
    const char* startArgs[] = {
        "p2pcert-daemon",
        "start",
        "--node-id", "test-node.example.com",
        "--addr", "127.0.0.1",
        "--port", "8444"
    };
    daemon->run(8, const_cast<char**>(startArgs));
    
    // Small delay to allow threads to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Create a test CSR file
    std::string csrPath = "/tmp/p2pca-test/test.csr";
    std::ofstream csrFile(csrPath);
    csrFile << "-----BEGIN CERTIFICATE REQUEST-----\n";
    csrFile << "MIICxzCCAa8CAQAwSDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQK\n";
    csrFile << "DAtFeGFtcGxlIE9yZzEWMBQGA1UEAwwNZXhhbXBsZS5sb2NhbDCCASIwDQYJKoZI\n";
    csrFile << "hvcNAQEBBQADggEPADCCAQoCggEBAMFDkfbeEBLvJtKXA9DJzJxP5kHCwJzv4cXr\n";
    csrFile << "JbcsV0AYKiJLYZqQVLEPPgJVnub9EVnrQKMn3K7UrECGERQHPZbwKOaIhF5rSEry\n";
    csrFile << "-----END CERTIFICATE REQUEST-----\n";
    csrFile.close();
    
    // Sign the CSR
    const char* signArgs[] = {
        "p2pcert-daemon",
        "sign",
        csrPath.c_str()
    };
    int result = daemon->run(3, const_cast<char**>(signArgs));
    EXPECT_EQ(result, 0);
    
    // Stop the daemon
    const char* stopArgs[] = {
        "p2pcert-daemon",
        "stop"
    };
    daemon->run(2, const_cast<char**>(stopArgs));
}

TEST_F(P2PCertDaemonCliTest, TestDaemonHelp) {
    const char* helpArgs[] = {
        "p2pcert-daemon",
        "help"
    };
    int result = daemon->run(2, const_cast<char**>(helpArgs));
    EXPECT_EQ(result, 0);
}

TEST_F(P2PCertDaemonCliTest, TestInvalidCommand) {
    const char* invalidArgs[] = {
        "p2pcert-daemon",
        "invalid-command"
    };
    int result = daemon->run(2, const_cast<char**>(invalidArgs));
    EXPECT_NE(result, 0);  // Should return non-zero for invalid command
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 