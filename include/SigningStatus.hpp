#ifndef SIGNING_STATUS_HPP
#define SIGNING_STATUS_HPP

enum class SigningStatus {
    Pending,
    Signed,
    Error,
    Rejected,
    NetworkError
};

class DomainValidator {
public:
    enum ValidationMethod { HTTP, DNS, EMAIL };
    
    static bool validateOwnership(const std::string& domain, ValidationMethod method);
    
private:
    static bool performHttpChallenge(const std::string& domain);
    static bool performDnsChallenge(const std::string& domain);
    static bool performEmailChallenge(const std::string& domain);
};

class AcmeClient {
    // Methods to handle ACME protocol interactions
    bool initiateChallenge(const std::string& domain);
    bool verifyChallenge();
    bool requestCertificate(const std::string& csr);
};

class CertificateManager {
public:
    void scheduleRenewal(const Certificate& cert, int daysBeforeExpiry = 30);
    bool renewCertificate(const Certificate& cert);
    
    // Monitoring
    std::vector<Certificate> getExpiringCertificates(int withinDays = 30);
};

class WebServerConfigurator {
public:
    enum ServerType { APACHE, NGINX, LIGHTTPD, OTHER };
    
    bool installCertificate(ServerType type, const Certificate& cert);
    bool configureHttpsRedirect(ServerType type);
};

class NodeAuthentication {
public:
    enum AuthMethod { PROOF_OF_WORK, PROOF_OF_STAKE, SOCIAL_GRAPH };
    
    bool authenticateNode(const FNode& node, AuthMethod method);
};

#endif // SIGNING_STATUS_HPP