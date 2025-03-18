#include <gtest/gtest.h>
#include "Certificate.hpp"
#include <openssl/evp.h>
#include <openssl/rsa.h>

class CertificateTest : public ::testing::Test {
protected:
    EVP_PKEY* testKey;

    void SetUp() override {
        // Generate a test key pair
        testKey = EVP_PKEY_new();
        RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
        EVP_PKEY_assign_RSA(testKey, rsa);
    }

    void TearDown() override {
        EVP_PKEY_free(testKey);
    }
};

TEST_F(CertificateTest, TestCreateCertificate) {
    EXPECT_NO_THROW({
        Certificate cert("test.example.com", "Test Org", "US");
    });
}

TEST_F(CertificateTest, TestGenerateAndSignCertificate) {
    Certificate cert("test.example.com", "Test Org", "US");
    EXPECT_TRUE(cert.generateX509(testKey));
    EXPECT_TRUE(cert.sign(testKey));
}

TEST_F(CertificateTest, TestVerifyCertificate) {
    Certificate cert("test.example.com", "Test Org", "US");
    cert.generateX509(testKey);
    cert.sign(testKey);
    EXPECT_TRUE(cert.verify(testKey));
}

TEST_F(CertificateTest, TestPEMSerialization) {
    Certificate cert("test.example.com", "Test Org", "US");
    cert.generateX509(testKey);
    cert.sign(testKey);
    
    std::string pem = cert.toPEM();
    EXPECT_FALSE(pem.empty());

    Certificate cert2;
    EXPECT_TRUE(cert2.fromPEM(pem));
} 