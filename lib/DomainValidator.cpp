#include "DomainValidator.hpp"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <curl/curl.h>
#include <sys/stat.h>

DomainValidator::DomainValidator() 
    : httpRootPath("/var/www/html"),
      dnsApiKey(""),
      contactEmail("") {
}

ValidationStatus DomainValidator::validateDomain(const std::string& domain, ValidationMethod method) {
    // Initialize ACME client first
    if (!acmeClient.initialize()) {
        std::cerr << "Failed to initialize ACME client" << std::endl;
        return ValidationStatus::Failed;
    }
    
    // Create an ACME account if needed
    if (!contactEmail.empty()) {
        acmeClient.createAccount(contactEmail);
    }
    
    // Create an order for the domain
    std::vector<std::string> domains = {domain};
    AcmeStatus status = acmeClient.createOrder(domains);
    if (status != AcmeStatus::Success) {
        return ValidationStatus::Failed;
    }
    
    // Get challenges
    status = acmeClient.getChallenges();
    if (status != AcmeStatus::PendingChallenge) {
        return ValidationStatus::Failed;
    }
    
    // Perform domain validation based on the method
    ValidationStatus validationStatus;
    switch (method) {
        case ValidationMethod::HTTP:
            validationStatus = performHttpChallenge(domain);
            break;
        case ValidationMethod::DNS:
            validationStatus = performDnsChallenge(domain);
            break;
        case ValidationMethod::EMAIL:
            validationStatus = performEmailChallenge(domain);
            break;
        default:
            validationStatus = ValidationStatus::Failed;
    }
    
    domainStatus[domain] = validationStatus;
    return validationStatus;
}

ValidationStatus DomainValidator::checkValidationStatus(const std::string& domain) {
    auto it = domainStatus.find(domain);
    if (it != domainStatus.end()) {
        return it->second;
    }
    return ValidationStatus::Failed;
}

ValidationStatus DomainValidator::performHttpChallenge(const std::string& domain) {
    // Get HTTP challenge token
    auto challenges = acmeClient.getHttpChallenges();
    auto it = challenges.find(domain);
    if (it == challenges.end()) {
        std::cerr << "No HTTP challenge found for domain: " << domain << std::endl;
        return ValidationStatus::Failed;
    }
    
    std::string token = it->second;
    std::string keyAuth = token + ".dummyThumbprint"; // Simplified for example
    
    // Create challenge file
    if (!createHttpChallengeFile(token, keyAuth)) {
        return ValidationStatus::Failed;
    }
    
    // Tell ACME server that challenge is ready
    acmeClient.completeHttpChallenge(domain, token);
    
    // Verify the challenge
    // For simplicity, we'll assume verification is successful
    // In a real implementation, we would poll for status
    
    return ValidationStatus::Success;
}

ValidationStatus DomainValidator::performDnsChallenge(const std::string& domain) {
    // Get DNS challenge digest
    auto challenges = acmeClient.getDnsChallenges();
    auto it = challenges.find(domain);
    if (it == challenges.end()) {
        std::cerr << "No DNS challenge found for domain: " << domain << std::endl;
        return ValidationStatus::Failed;
    }
    
    std::string digest = it->second;
    
    // Create DNS TXT record
    if (!createDnsTxtRecord(domain, digest)) {
        return ValidationStatus::Failed;
    }
    
    // Wait for DNS propagation (real implementation would check)
    std::this_thread::sleep_for(std::chrono::seconds(10));
    
    // Tell ACME server that challenge is ready
    acmeClient.completeDnsChallenge(domain, digest);
    
    // In a real implementation, we would poll for status
    
    return ValidationStatus::Success;
}

ValidationStatus DomainValidator::performEmailChallenge(const std::string& domain) {
    // Email validation is not part of ACME, but we'll simulate it
    // Generate a random code
    std::string code = "123456"; // In a real implementation, generate a random code
    
    // Send validation email
    if (!sendValidationEmail(domain, code)) {
        return ValidationStatus::Failed;
    }
    
    // In a real implementation, we would wait for user input with the code
    // For this example, we'll just assume it's successful
    
    return ValidationStatus::Success;
}

bool DomainValidator::createHttpChallengeFile(const std::string& token, const std::string& content) {
    // Create .well-known/acme-challenge directory if it doesn't exist
    std::string acmeDir = httpRootPath + "/.well-known/acme-challenge";
    std::string command = "mkdir -p " + acmeDir;
    int result = std::system(command.c_str());
    
    if (result != 0) {
        std::cerr << "Failed to create challenge directory" << std::endl;
        return false;
    }
    
    // Create challenge file
    std::string filePath = acmeDir + "/" + token;
    std::ofstream file(filePath);
    
    if (!file) {
        std::cerr << "Failed to create challenge file: " << filePath << std::endl;
        return false;
    }
    
    file << content;
    file.close();
    
    // Make sure the file is readable by web server
    chmod(filePath.c_str(), 0644);
    
    std::cout << "Created HTTP challenge file at: " << filePath << std::endl;
    return true;
}

bool DomainValidator::createDnsTxtRecord(const std::string& domain, const std::string& digest) {
    // In a real implementation, this would use DNS provider APIs
    // For example, using Cloudflare, AWS Route53, etc.
    
    if (dnsApiKey.empty()) {
        std::cerr << "DNS API key not provided" << std::endl;
        return false;
    }
    
    std::cout << "DNS Challenge: Create TXT record for _acme-challenge." << domain << std::endl;
    std::cout << "With value: " << digest << std::endl;
    
    // Simulate API call
    std::cout << "Using DNS API key: " << dnsApiKey << std::endl;
    
    return true;
}

bool DomainValidator::sendValidationEmail(const std::string& domain, const std::string& code) {
    // In a real implementation, this would send an email
    // For this example, we'll just log it
    
    std::cout << "Sending validation email to admin@" << domain << std::endl;
    std::cout << "Validation code: " << code << std::endl;
    
    return true;
} 