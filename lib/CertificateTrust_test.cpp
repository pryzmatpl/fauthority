#include <gtest/gtest.h>
#include "CertificateTrust.hpp"
#include "Certificate.hpp"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <fstream>
#include <cstdio>

class CertificateTrustTest : public ::testing::Test {
protected:
    EVP_PKEY* testKey;
    Certificate* testCert;
    
    void SetUp() override {
        testKey = EVP_PKEY_new();
        RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
        EVP_PKEY_assign_RSA(testKey, rsa);
        
        testCert = new Certificate("test.example.com", "Test Org", "US");
        testCert->generateX509(testKey);
        testCert->sign(testKey);
    }
    
    void TearDown() override {
        EVP_PKEY_free(testKey);
        delete testCert;
    }
};

TEST_F(CertificateTrustTest, TestExportForWebServer) {
    std::string testPath = "/tmp/test_cert.pem";
    EXPECT_TRUE(CertificateTrust::exportForWebServer(*testCert, testPath));
    
    // Verify the file exists and contains certificate data
    std::ifstream certFile(testPath);
    EXPECT_TRUE(certFile.good());
    
    std::string fileContent((std::istreambuf_iterator<char>(certFile)),
                            std::istreambuf_iterator<char>());
    EXPECT_FALSE(fileContent.empty());
    
    // Clean up
    certFile.close();
    std::remove(testPath.c_str());
}

// Note: The following tests are commented out because they would require
// system-level permissions and would modify the system certificate store
/*
TEST_F(CertificateTrustTest, TestInstallInSystemStore) {
    EXPECT_TRUE(CertificateTrust::installInSystemStore(*testCert));
}

TEST_F(CertificateTrustTest, TestVerifyAgainstSystemStore) {
    // First install the certificate
    EXPECT_TRUE(CertificateTrust::installInSystemStore(*testCert));
    
    // Then verify it
    EXPECT_TRUE(CertificateTrust::verifyAgainstSystemStore(*testCert));
}
*/ 