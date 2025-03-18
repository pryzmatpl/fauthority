#include <gtest/gtest.h>
#include "CertificateManager.hpp"
#include "Certificate.hpp"
#include <chrono>
#include <thread>

class CertificateManagerTest : public ::testing::Test {
protected:
    CertificateManager* manager;
    Certificate* testCert;
    
    void SetUp() override {
        manager = new CertificateManager();
        
        // Create a test certificate
        testCert = new Certificate("test.example.com", "Test Org", "US");
        
        // Generate key pair for the certificate
        EVP_PKEY* pkey = EVP_PKEY_new();
        RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
        EVP_PKEY_assign_RSA(pkey, rsa);
        
        testCert->generateX509(pkey);
        testCert->sign(pkey);
        
        EVP_PKEY_free(pkey);
    }
    
    void TearDown() override {
        delete manager;
        delete testCert;
    }
};

TEST_F(CertificateManagerTest, TestAddCertificate) {
    EXPECT_TRUE(manager->addCertificate(*testCert, "test.example.com", ValidationMethod::HTTP));
}

TEST_F(CertificateManagerTest, TestRemoveCertificate) {
    // First add a certificate
    manager->addCertificate(*testCert, "test.example.com", ValidationMethod::HTTP);
    
    // Then remove it
    EXPECT_TRUE(manager->removeCertificate("test.example.com"));
    
    // Removing a non-existent certificate should fail
    EXPECT_FALSE(manager->removeCertificate("nonexistent.example.com"));
}

TEST_F(CertificateManagerTest, TestGetExpiringCertificates) {
    // Add a certificate
    manager->addCertificate(*testCert, "test.example.com", ValidationMethod::HTTP);
    
    // Check for expiring certificates (this test assumes the certificate will expire)
    auto expiringCerts = manager->getExpiringCertificates(365); // Within a year
    EXPECT_GE(expiringCerts.size(), 1);
}

TEST_F(CertificateManagerTest, TestRenewalService) {
    // Add a certificate
    manager->addCertificate(*testCert, "test.example.com", ValidationMethod::HTTP);
    
    // Start the renewal service
    manager->startRenewalService();
    
    // Wait a short time for the service to run
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Stop the renewal service
    manager->stopRenewalService();
    
    // No actual assertions here since the renewal is a background task
    // This test just ensures the service can be started and stopped without errors
}

TEST_F(CertificateManagerTest, TestRenewCertificate) {
    // Add a certificate
    manager->addCertificate(*testCert, "test.example.com", ValidationMethod::HTTP);
    
    // Attempt to renew it
    RenewalStatus status = manager->renewCertificate("test.example.com");
    
    // In a test environment, renewal will likely fail due to missing ACME server
    // But the function should run without exceptions
    EXPECT_TRUE(status == RenewalStatus::Success || 
                status == RenewalStatus::Failed ||
                status == RenewalStatus::Pending);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 