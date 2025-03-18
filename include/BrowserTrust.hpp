#ifndef BROWSER_TRUST_HPP
#define BROWSER_TRUST_HPP

#include <string>
#include <vector>
#include <map>
#include "Certificate.hpp"

enum class TrustStrategy {
    LocalTrust,       // Install in local trust store
    CrossSigning,     // Get CA to cross-sign
    WebOfTrust,       // PGP-like web of trust
    TrustOnFirstUse   // TOFU model
};

enum class TrustStatus {
    Trusted,
    Untrusted,
    Unknown,
    Error
};

class BrowserTrust {
public:
    BrowserTrust();
    
    // Trust strategies
    TrustStatus establishLocalTrust(const Certificate& cert);
    TrustStatus establishCrossSigning(const Certificate& cert, const std::string& caName);
    TrustStatus establishWebOfTrust(const Certificate& cert, int requiredSignatures = 3);
    TrustStatus establishTOFU(const Certificate& cert, const std::string& domain);
    
    // Generate root CA for the P2P network
    bool generateRootCA(const std::string& commonName, 
                       const std::string& organization,
                       const std::string& country);
    
    // Setup
    void setRootCAPath(const std::string& path) { rootCAPath = path; }
    void setTrustStorePath(const std::string& path) { trustStorePath = path; }
    void addTrustedSignatory(const std::string& id) { trustedSignatories.push_back(id); }
    
    std::string getLastError() const { return lastError; }
    
private:
    std::string rootCAPath;
    std::string trustStorePath;
    std::vector<std::string> trustedSignatories;
    std::string lastError;
    
    // Trust store management
    bool installInLocalTrustStore(const Certificate& cert);
    bool removeFromLocalTrustStore(const Certificate& cert);
    
    // Cross-signing
    bool requestCrossSigning(const Certificate& cert, const std::string& caName);
    
    // Web of Trust
    int countTrustedSignatures(const Certificate& cert);
    bool addSignatureToWebOfTrust(const Certificate& cert, const std::string& signatory);
    
    // Trust on First Use
    bool recordFirstUse(const Certificate& cert, const std::string& domain);
    bool hasRecordedCertificate(const std::string& domain);
    bool certificateMatchesRecord(const Certificate& cert, const std::string& domain);
};

#endif // BROWSER_TRUST_HPP 