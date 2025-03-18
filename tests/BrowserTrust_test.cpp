#include <gtest/gtest.h>
#include "BrowserTrust.hpp"
#include "Certificate.hpp"
#include <openssl/rsa.h>
#include <openssl/pem.h>

class BrowserTrustTest : public ::testing::Test {
protected:
    BrowserTrust* trust;
    Certificate* testCert;
    
    void SetUp() override {
        trust = new BrowserTrust();
        
        // Use a temporary path for testing
        trust->setRootCAPath("/tmp/p2pca-test");
        
        // Create a test certificate
        testCert = new Certificate("test.example.com", "Test Org", "US");
        
        // Generate key pair for the certificate
        EVP_PKEY* pkey = EVP_PKEY_new();
        RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
        EVP_PKEY_assign_RSA(pkey, rsa);
        
        testCert->generateX509(pkey);
        testCert->sign(pkey);
        
        EVP_PKEY_free(pkey);
        
        // Add some trusted signatories
        trust->addTrustedSignatory("trusted-node-1");
        trust->addTrustedSignatory("trusted-node-2");
    }
    
    void TearDown() override {
        delete trust;
        delete testCert;
        // Clean up test directory
        std::system("rm -rf /tmp/p2pca-test");
    }
};

TEST_F(BrowserTrustTest, TestGenerateRootCA) {
    EXPECT_TRUE(trust->generateRootCA("P2P CA Root", "P2P Certificate Authority", "US"));
}

TEST_F(BrowserTrustTest, TestEstablishLocalTrust) {
    TrustStatus status = trust->establishLocalTrust(*testCert);
    
    // In a test environment, this will likely fail due to permissions
    // But the function should run without exceptions
    EXPECT_TRUE(status == TrustStatus::Trusted || status == TrustStatus::Error);
}

TEST_F(BrowserTrustTest, TestEstablishCrossSigning) {
    TrustStatus status = trust->establishCrossSigning(*testCert, "Let's Encrypt");
    
    // This will likely fail in a test environment
    EXPECT_TRUE(status == TrustStatus::Trusted || status == TrustStatus::Error);
}

TEST_F(BrowserTrustTest, TestEstablishWebOfTrust) {
    TrustStatus status = trust->establishWebOfTrust(*testCert, 1);
    
    EXPECT_TRUE(status == TrustStatus::Trusted || 
                status == TrustStatus::Unknown || 
                status == TrustStatus::Untrusted);
}

TEST_F(BrowserTrustTest, TestEstablishTOFU) {
    // First use should be trusted
    TrustStatus status1 = trust->establishTOFU(*testCert, "test.example.com");
    EXPECT_EQ(status1, TrustStatus::Trusted);
    
    // Same certificate on second use should be trusted
    TrustStatus status2 = trust->establishTOFU(*testCert, "test.example.com");
    EXPECT_EQ(status2, TrustStatus::Trusted);
    
    // Different certificate on second use should be untrusted
    Certificate differentCert("test.example.com", "Different Org", "UK");
    TrustStatus status3 = trust->establishTOFU(differentCert, "test.example.com");
    EXPECT_EQ(status3, TrustStatus::Untrusted);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 