#include <gtest/gtest.h>
#include "IncomingRequest.hpp"
#include <openssl/evp.h>
#include <openssl/rsa.h>

class IncomingRequestTest : public ::testing::Test {
protected:
    EVP_PKEY* testKey;
    Certificate* testCert;
    std::string testAddress;

    void SetUp() override {
        testKey = EVP_PKEY_new();
        RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
        EVP_PKEY_assign_RSA(testKey, rsa);

        testCert = new Certificate("test.example.com", "Test Org", "US");
        testCert->generateX509(testKey);
        testCert->sign(testKey);

        testAddress = "192.168.1.100";
    }

    void TearDown() override {
        EVP_PKEY_free(testKey);
        delete testCert;
    }

    std::string createTestRequestData(RequestType type) {
        std::string typeStr = (type == RequestType::SIGN_CERTIFICATE) ? "SIGN" : "VERIFY";
        return typeStr + "\n" + testCert->toPEM();
    }
};

TEST_F(IncomingRequestTest, TestCreateRequest) {
    std::string requestData = createTestRequestData(RequestType::SIGN_CERTIFICATE);
    EXPECT_NO_THROW({
        IncomingRequest request(requestData, testAddress);
    });
}

TEST_F(IncomingRequestTest, TestParseValidRequest) {
    std::string requestData = createTestRequestData(RequestType::SIGN_CERTIFICATE);
    IncomingRequest request(requestData, testAddress);
    EXPECT_TRUE(request.parse());
    EXPECT_EQ(request.getType(), RequestType::SIGN_CERTIFICATE);
}

TEST_F(IncomingRequestTest, TestParseInvalidRequest) {
    IncomingRequest request("INVALID\nDATA", testAddress);
    EXPECT_FALSE(request.parse());
    EXPECT_EQ(request.getType(), RequestType::UNKNOWN);
}

TEST_F(IncomingRequestTest, TestSerializeDeserialize) {
    std::string requestData = createTestRequestData(RequestType::SIGN_CERTIFICATE);
    IncomingRequest original(requestData, testAddress);
    original.parse();

    std::string serialized = original.serialize();
    IncomingRequest deserialized = IncomingRequest::deserialize(serialized);
    
    EXPECT_EQ(deserialized.getType(), original.getType());
} 