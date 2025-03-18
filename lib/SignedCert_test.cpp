#include <gtest/gtest.h>
#include "SignedCert.hpp"
#include <openssl/evp.h>
#include <openssl/rsa.h>

class SignedCertTest : public ::testing::Test {
protected:
    EVP_PKEY* testKey;
    Certificate* testCert;
    std::vector<unsigned char> testSignature;

    void SetUp() override {
        // Generate a test key pair
        testKey = EVP_PKEY_new();
        RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
        EVP_PKEY_assign_RSA(testKey, rsa);

        // Create a test certificate
        testCert = new Certificate("test.example.com", "Test Org", "US");
        testCert->generateX509(testKey);
        testCert->sign(testKey);

        // Create a test signature
        testSignature = std::vector<unsigned char>(256, 0x42);
    }

    void TearDown() override {
        EVP_PKEY_free(testKey);
        delete testCert;
    }
};

TEST_F(SignedCertTest, TestCreateSignedCert) {
    EXPECT_NO_THROW({
        SignedCert signedCert(*testCert, testSignature);
    });
}

TEST_F(SignedCertTest, TestVerifySignedCert) {
    SignedCert signedCert(*testCert, testSignature);
    
    // Convert public key to PEM format for verification
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, testKey);
    char* data;
    long len = BIO_get_mem_data(bio, &data);
    std::string pubKeyPEM(data, len);
    BIO_free(bio);

    EXPECT_TRUE(signedCert.verify(pubKeyPEM));
}

TEST_F(SignedCertTest, TestSerializeDeserialize) {
    SignedCert signedCert(*testCert, testSignature);
    std::string serialized = signedCert.serialize();
    EXPECT_FALSE(serialized.empty());

    SignedCert deserializedCert;
    EXPECT_TRUE(deserializedCert.deserialize(serialized));
    EXPECT_EQ(deserializedCert.getSignature(), testSignature);
}

TEST_F(SignedCertTest, TestSendBack) {
    SignedCert signedCert(*testCert, testSignature);
    EXPECT_TRUE(signedCert.sendBack());
} 