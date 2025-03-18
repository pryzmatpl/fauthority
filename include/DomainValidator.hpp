#ifndef DOMAIN_VALIDATOR_HPP
#define DOMAIN_VALIDATOR_HPP

#include <string>
#include <vector>
#include <map>
#include <functional>
#include "AcmeClient.hpp"

enum class ValidationMethod {
    HTTP,
    DNS,
    EMAIL
};

enum class ValidationStatus {
    Success,
    Pending,
    Failed,
    Unauthorized
};

class DomainValidator {
public:
    DomainValidator();
    
    ValidationStatus validateDomain(const std::string& domain, ValidationMethod method);
    ValidationStatus checkValidationStatus(const std::string& domain);
    
    void setHttpRootPath(const std::string& path) { httpRootPath = path; }
    void setDnsApiKey(const std::string& key) { dnsApiKey = key; }
    void setEmailContact(const std::string& email) { contactEmail = email; }
    
private:
    std::string httpRootPath;
    std::string dnsApiKey;
    std::string contactEmail;
    AcmeClient acmeClient;
    std::map<std::string, ValidationStatus> domainStatus;
    
    ValidationStatus performHttpChallenge(const std::string& domain);
    ValidationStatus performDnsChallenge(const std::string& domain);
    ValidationStatus performEmailChallenge(const std::string& domain);
    
    bool createHttpChallengeFile(const std::string& token, const std::string& content);
    bool createDnsTxtRecord(const std::string& domain, const std::string& digest);
    bool sendValidationEmail(const std::string& domain, const std::string& code);
};

#endif // DOMAIN_VALIDATOR_HPP 