#include <gtest/gtest.h>
#include "FSigner.hpp"
#include "SigningRequest.hpp"
#include "IncomingRequest.hpp"
#include <fstream>

class FSignerTest : public ::testing::Test {
protected:
    FSigner* signer;

    void SetUp() override {
        signer = new FSigner();
    }

    void TearDown() override {
        delete signer;
    }

    // Helper function to create a dummy private key for testing
    void createDummyPrivateKey() {
        RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
        FILE* privateKeyFile = fopen("private_key.pem", "wb");
        PEM_write_RSAPrivateKey(privateKeyFile, rsa, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(privateKeyFile);
        RSA_free(rsa);
    }

    // Helper function to remove the dummy private key after tests
    void removeDummyPrivateKey() {
        std::remove("private_key.pem");
    }
};

TEST_F(FSignerTest, TestCreateFSigner) {
    EXPECT_NO_THROW(FSigner());
}

TEST_F(FSignerTest, TestGetSigningRequests) {
    std::vector<IncomingRequest> incomingRequests(5); // Create 5 dummy incoming requests
    auto signingRequests = signer->getSigningRequests(incomingRequests);
    EXPECT_EQ(signingRequests.size(), incomingRequests.size());
}

TEST_F(FSignerTest, TestSignCertificateFromRequest) {
    // Create a dummy private key for testing
    createDummyPrivateKey();

    SigningRequest request; // Create a dummy signing request
    SigningStatus status = signer->signCertificateFromRequest(request);
    EXPECT_EQ(status, SigningStatus::Signed);

    // Clean up the dummy private key
    removeDummyPrivateKey();
}

TEST_F(FSignerTest, TestSignCertificateFromRequestWithInvalidKey) {
    // Create a dummy signing request
    SigningRequest request;

    // Temporarily remove the private key file to simulate an error
    removeDummyPrivateKey();

    SigningStatus status = signer->signCertificateFromRequest(request);
    EXPECT_EQ(status, SigningStatus::Error);
}

TEST_F(FSignerTest, TestGetCertUsingSigningStatus) {
    SignedCert cert = signer->getCertUsingSigningStatus(SigningStatus::Signed);
    EXPECT_NO_THROW(cert.sendBack()); // Ensure sendBack does not throw
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 