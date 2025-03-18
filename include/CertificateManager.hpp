#ifndef CERTIFICATE_MANAGER_HPP
#define CERTIFICATE_MANAGER_HPP

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include "Certificate.hpp"
#include "AcmeClient.hpp"
#include "DomainValidator.hpp"

struct ManagedCertificate {
    Certificate cert;
    std::string domain;
    std::chrono::system_clock::time_point expiryDate;
    std::chrono::system_clock::time_point renewalDate;
    ValidationMethod validationMethod;
    bool autoRenew;
};

enum class RenewalStatus {
    Success,
    Failed,
    Pending,
    NotNeeded
};

class CertificateManager {
public:
    CertificateManager();
    ~CertificateManager();
    
    bool addCertificate(const Certificate& cert, const std::string& domain, 
                        ValidationMethod method, bool autoRenew = true);
    bool removeCertificate(const std::string& domain);
    std::vector<ManagedCertificate> getExpiringCertificates(int withinDays = 30);
    RenewalStatus renewCertificate(const std::string& domain);
    RenewalStatus renewAllCertificates();
    
    void setRenewalDays(int days) { daysBeforeRenewal = days; }
    void startRenewalService();
    void stopRenewalService();
    
private:
    std::map<std::string, ManagedCertificate> certificates;
    AcmeClient acmeClient;
    DomainValidator domainValidator;
    int daysBeforeRenewal;
    
    std::thread renewalThread;
    std::atomic<bool> running;
    std::mutex mutex;
    std::condition_variable cv;
    
    void renewalService();
    std::chrono::system_clock::time_point calculateExpiryDate(const Certificate& cert) const;
    std::chrono::system_clock::time_point calculateRenewalDate(
        const std::chrono::system_clock::time_point& expiryDate) const;
    bool saveCertificate(const std::string& domain, const std::string& certData);
};

#endif // CERTIFICATE_MANAGER_HPP 