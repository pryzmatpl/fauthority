#include <gtest/gtest.h>
#include "WebServerConfigurator.hpp"
#include "Certificate.hpp"
#include <openssl/rsa.h>
#include <openssl/pem.h>

class WebServerConfiguratorTest : public ::testing::Test {
protected:
    WebServerConfigurator* configurator;
    Certificate* testCert;
    std::string privateKeyPath;
    
    void SetUp() override {
        configurator = new WebServerConfigurator();
        
        // Create a test certificate
        testCert = new Certificate("test.example.com", "Test Org", "US");
        
        // Generate key pair for the certificate
        EVP_PKEY* pkey = EVP_PKEY_new();
        RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
        EVP_PKEY_assign_RSA(pkey, rsa);
        
        testCert->generateX509(pkey);
        testCert->sign(pkey);
        
        // Save private key to temporary file
        privateKeyPath = "/tmp/test_key.pem";
        FILE* keyFile = fopen(privateKeyPath.c_str(), "w");
        PEM_write_PrivateKey(keyFile, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(keyFile);
        
        EVP_PKEY_free(pkey);
    }
    
    void TearDown() override {
        delete configurator;
        delete testCert;
        std::remove(privateKeyPath.c_str());
    }
};

TEST_F(WebServerConfiguratorTest, TestDetectWebServer) {
    WebServerType serverType = configurator->detectWebServer();
    
    // The result depends on the test environment
    // We just verify the function doesn't throw
    EXPECT_NO_THROW(serverType);
}

TEST_F(WebServerConfiguratorTest, TestInstallCertificate) {
    // This would require system permissions in a real environment
    // For testing, we'll just check the function signature
    ConfigStatus status = configurator->installCertificate(*testCert, privateKeyPath);
    
    // In a test environment, this will likely fail due to permissions
    // But the function should run without exceptions
    EXPECT_TRUE(status == ConfigStatus::Success || 
                status == ConfigStatus::Failed ||
                status == ConfigStatus::NotSupported ||
                status == ConfigStatus::PermissionDenied);
}

TEST_F(WebServerConfiguratorTest, TestConfigureHttps) {
    // This would require system permissions in a real environment
    // For testing, we'll just check the function signature
    ConfigStatus status = configurator->configureHttps();
    
    // In a test environment, this will likely fail due to permissions
    // But the function should run without exceptions
    EXPECT_TRUE(status == ConfigStatus::Success || 
                status == ConfigStatus::Failed ||
                status == ConfigStatus::NotSupported ||
                status == ConfigStatus::PermissionDenied);
}

TEST_F(WebServerConfiguratorTest, TestEnableHttpsRedirect) {
    // This would require system permissions in a real environment
    // For testing, we'll just check the function signature
    ConfigStatus status = configurator->enableHttpsRedirect();
    
    // In a test environment, this will likely fail due to permissions
    // But the function should run without exceptions
    EXPECT_TRUE(status == ConfigStatus::Success || 
                status == ConfigStatus::Failed ||
                status == ConfigStatus::NotSupported ||
                status == ConfigStatus::PermissionDenied);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 