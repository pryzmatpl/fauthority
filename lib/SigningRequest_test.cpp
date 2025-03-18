#include <gtest/gtest.h>
#include "SigningRequest.hpp"
#include <openssl/evp.h>
#include <openssl/rsa.h>

class SigningRequestTest : public ::testing::Test {
protected:
    EVP_PKEY* testKey;
    Certificate* testCert;
    std::string testAddress;
    IncomingRequest* testIncoming;

    void SetUp() override {
        testKey = EVP_PKEY_new();
        RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
        EVP_PKEY_assign_RSA(testKey, rsa);

        testCert = new Certificate("test.example.com", "Test Org", "US");
        testCert->generateX509(testKey);
        testCert->sign(testKey);

        testAddress = "192.168.1.100";
        
        std::string requestData = "SIGN\n" + testCert->toPEM();
        testIncoming = new IncomingRequest(requestData, testAddress);
        testIncoming->parse();
    }

    void TearDown() override {
        EVP_PKEY_free(testKey);
        delete testCert;
        delete testIncoming;
    }
};

TEST_F(SigningRequestTest, TestCreateSigningRequest) {
    EXPECT_NO_THROW({
        SigningRequest request(*testIncoming);
    });
}

TEST_F(SigningRequestTest, TestValidSigningRequest) {
    SigningRequest request(*testIncoming);
    EXPECT_TRUE(request.isValid());
    EXPECT_EQ(request.getRequesterAddress(), testAddress);
}

TEST_F(SigningRequestTest, TestInvalidSigningRequest) {
    IncomingRequest invalidRequest("VERIFY\nInvalid Certificate", "");
    SigningRequest request(invalidRequest);
    EXPECT_FALSE(request.isValid());
}

TEST_F(SigningRequestTest, TestGetCertificate) {
    SigningRequest request(*testIncoming);
    EXPECT_NO_THROW({
        Certificate cert = request.getCertificate();
    });
} 