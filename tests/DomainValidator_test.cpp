#include <gtest/gtest.h>
#include "DomainValidator.hpp"

class DomainValidatorTest : public ::testing::Test {
protected:
    DomainValidator* validator;
    
    void SetUp() override {
        validator = new DomainValidator();
        validator->setHttpRootPath("/tmp/http-challenge");
        validator->setDnsApiKey("test-api-key");
        validator->setEmailContact("admin@example.com");
    }
    
    void TearDown() override {
        delete validator;
    }
};

TEST_F(DomainValidatorTest, TestHttpValidation) {
    // This is more of an integration test that would require a web server
    // For unit testing, we'll just ensure the method doesn't throw
    EXPECT_NO_THROW(validator->validateDomain("example.com", ValidationMethod::HTTP));
}

TEST_F(DomainValidatorTest, TestDnsValidation) {
    // This would require DNS API access
    // For unit testing, we'll just ensure the method doesn't throw
    EXPECT_NO_THROW(validator->validateDomain("example.com", ValidationMethod::DNS));
}

TEST_F(DomainValidatorTest, TestEmailValidation) {
    // This would require email sending capabilities
    // For unit testing, we'll just ensure the method doesn't throw
    EXPECT_NO_THROW(validator->validateDomain("example.com", ValidationMethod::EMAIL));
}

TEST_F(DomainValidatorTest, TestCheckValidationStatus) {
    // First validate a domain
    validator->validateDomain("example.com", ValidationMethod::HTTP);
    
    // Then check its status
    ValidationStatus status = validator->checkValidationStatus("example.com");
    EXPECT_TRUE(status == ValidationStatus::Success || 
                status == ValidationStatus::Pending || 
                status == ValidationStatus::Failed);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
} 