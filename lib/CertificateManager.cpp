#include "CertificateManager.hpp"
#include <iostream>
#include <fstream>
#include <ctime>
#include <algorithm>
#include <openssl/x509.h>
#include <openssl/pem.h>

CertificateManager::CertificateManager() 
    : daysBeforeRenewal(30), running(false) {
}

CertificateManager::~CertificateManager() {
    stopRenewalService();
}

bool CertificateManager::addCertificate(const Certificate& cert, const std::string& domain, 
                                       ValidationMethod method, bool autoRenew) {
    ManagedCertificate managedCert;
    managedCert.cert = cert;
    managedCert.domain = domain;
    managedCert.expiryDate = calculateExpiryDate(cert);
    managedCert.renewalDate = calculateRenewalDate(managedCert.expiryDate);
    managedCert.validationMethod = method;
    managedCert.autoRenew = autoRenew;
    
    std::lock_guard<std::mutex> lock(mutex);
    certificates[domain] = managedCert;
    
    return true;
}

bool CertificateManager::removeCertificate(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex);
    auto it = certificates.find(domain);
    if (it != certificates.end()) {
        certificates.erase(it);
        return true;
    }
    return false;
}

std::vector<ManagedCertificate> CertificateManager::getExpiringCertificates(int withinDays) const {
    std::vector<ManagedCertificate> expiringCerts;
    auto now = std::chrono::system_clock::now();
    auto threshold = now + std::chrono::hours(24 * withinDays);
    
    std::lock_guard<std::mutex> lock(mutex);
    for (const auto& entry : certificates) {
        if (entry.second.expiryDate <= threshold) {
            expiringCerts.push_back(entry.second);
        }
    }
    
    return expiringCerts;
}

RenewalStatus CertificateManager::renewCertificate(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex);
    auto it = certificates.find(domain);
    if (it == certificates.end()) {
        return RenewalStatus::Failed;
    }
    
    ManagedCertificate& managedCert = it->second;
    
    // Initialize ACME client
    if (!acmeClient.initialize()) {
        std::cerr << "Failed to initialize ACME client for renewal" << std::endl;
        return RenewalStatus::Failed;
    }
    
    // Create account
    acmeClient.createAccount("admin@" + domain);
    
    // Create order
    std::vector<std::string> domains = {domain};
    AcmeStatus status = acmeClient.createOrder(domains);
    if (status != AcmeStatus::Success) {
        return RenewalStatus::Failed;
    }
    
    // Validate domain
    ValidationStatus valStatus = domainValidator.validateDomain(domain, managedCert.validationMethod);
    if (valStatus != ValidationStatus::Success) {
        return RenewalStatus::Failed;
    }
    
    // Generate CSR
    // In a real implementation, this would be:
    // - Create a new key pair
    // - Generate a CSR for the domain
    std::string csr = "dummy-csr"; // Placeholder
    
    // Finalize order
    status = acmeClient.finalizeOrder(csr);
    if (status != AcmeStatus::Success) {
        return RenewalStatus::Failed;
    }
    
    // Download certificate
    std::string certData = acmeClient.downloadCertificate();
    if (certData.empty()) {
        return RenewalStatus::Failed;
    }
    
    // Save the new certificate
    if (!saveCertificate(domain, certData)) {
        return RenewalStatus::Failed;
    }
    
    // Update certificate information
    // In a real implementation, create a new Certificate object from the downloaded cert
    Certificate newCert = managedCert.cert; // Placeholder
    
    managedCert.cert = newCert;
    managedCert.expiryDate = calculateExpiryDate(newCert);
    managedCert.renewalDate = calculateRenewalDate(managedCert.expiryDate);
    
    std::cout << "Certificate for " << domain << " renewed successfully." << std::endl;
    return RenewalStatus::Success;
}

RenewalStatus CertificateManager::renewAllCertificates() {
    bool allSuccess = true;
    
    std::lock_guard<std::mutex> lock(mutex);
    for (auto& entry : certificates) {
        if (entry.second.autoRenew) {
            RenewalStatus status = renewCertificate(entry.first);
            if (status != RenewalStatus::Success) {
                allSuccess = false;
            }
        }
    }
    
    return allSuccess ? RenewalStatus::Success : RenewalStatus::Failed;
}

void CertificateManager::startRenewalService() {
    if (running) {
        return;
    }
    
    running = true;
    renewalThread = std::thread(&CertificateManager::renewalService, this);
}

void CertificateManager::stopRenewalService() {
    if (!running) {
        return;
    }
    
    {
        std::lock_guard<std::mutex> lock(mutex);
        running = false;
    }
    
    cv.notify_one();
    
    if (renewalThread.joinable()) {
        renewalThread.join();
    }
}

void CertificateManager::renewalService() {
    while (running) {
        // Check for certificates that need renewal
        auto expiringCerts = getExpiringCertificates(daysBeforeRenewal);
        
        for (const auto& cert : expiringCerts) {
            if (cert.autoRenew) {
                std::cout << "Auto-renewing certificate for " << cert.domain << std::endl;
                renewCertificate(cert.domain);
            }
        }
        
        // Sleep until next check (24 hours)
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait_for(lock, std::chrono::hours(24), [this]{ return !running; });
    }
}

std::chrono::system_clock::time_point CertificateManager::calculateExpiryDate(const Certificate& cert) const {
    // In a real implementation, extract this from the X509 certificate
    // For this example, we'll return a date 90 days from now
    return std::chrono::system_clock::now() + std::chrono::hours(24 * 90);
}

std::chrono::system_clock::time_point CertificateManager::calculateRenewalDate(
    const std::chrono::system_clock::time_point& expiryDate) const {
    // Calculate renewal date based on expiry date and daysBeforeRenewal
    return expiryDate - std::chrono::hours(24 * daysBeforeRenewal);
}

bool CertificateManager::saveCertificate(const std::string& domain, const std::string& certData) {
    // In a real implementation, save to a file in a secure location
    std::string certPath = "/etc/ssl/certs/" + domain + ".pem";
    std::ofstream file(certPath);
    
    if (!file) {
        std::cerr << "Failed to save certificate to " << certPath << std::endl;
        return false;
    }
    
    file << certData;
    file.close();
    
    std::cout << "Certificate saved to " << certPath << std::endl;
    return true;
} 