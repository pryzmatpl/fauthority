#include <gtest/gtest.h>
#include "AcmeClient.hpp"
#include <openssl/pem.h>
#include <openssl/rsa.h>

class AcmeClientTest : public ::testing::Test {
protected:
    AcmeClient* client;
    
    void SetUp() override {
        // Use a mock ACME directory for testing
        client = new AcmeClient("https://mock-acme-directory.example.com");
    }
    
    void TearDown() override {
        delete client;
    }
};

TEST_F(AcmeClientTest, TestInitialize) {
    // This would normally connect to the ACME server
    // For testing, we'll just verify the function exists
    EXPECT_NO_THROW(client->initialize());
}

TEST_F(AcmeClientTest, TestCreateAccount) {
    EXPECT_NO_THROW(client->createAccount("test@example.com"));
}

TEST_F(AcmeClientTest, TestCreateOrder) {
    std::vector<std::string> domains = {"example.com", "www.example.com"};
    EXPECT_NO_THROW(client->createOrder(domains));
}

TEST_F(AcmeClientTest, TestGetChallenges) {
    EXPECT_NO_THROW(client->getChallenges());
}

TEST_F(AcmeClientTest, TestCompleteHttpChallenge) {
    EXPECT_NO_THROW(client->completeHttpChallenge("example.com", "token123"));
}

TEST_F(AcmeClientTest, TestCompleteDnsChallenge) {
    EXPECT_NO_THROW(client->completeDnsChallenge("example.com", "digest123"));
}

TEST_F(AcmeClientTest, TestFinalizeOrder) {
    // Create a dummy CSR
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    EVP_PKEY_assign_RSA(pkey, rsa);
    
    X509_REQ* req = X509_REQ_new();
    X509_REQ_set_pubkey(req, pkey);
    X509_REQ_sign(req, pkey, EVP_sha256());
    
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(bio, req);
    
    char* data;
    long len = BIO_get_mem_data(bio, &data);
    std::string csr(data, len);
    
    EXPECT_NO_THROW(client->finalizeOrder(csr));
    
    BIO_free(bio);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 