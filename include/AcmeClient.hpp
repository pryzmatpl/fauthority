#ifndef ACME_CLIENT_HPP
#define ACME_CLIENT_HPP

#include <string>
#include <vector>
#include <map>
#include "Certificate.hpp"

enum class AcmeStatus {
    Success,
    PendingChallenge,
    ChallengeFailed,
    AuthorizationFailed,
    OrderFailed,
    NetworkError
};

class AcmeClient {
public:
    AcmeClient(const std::string& directoryUrl = "https://acme-v02.api.letsencrypt.org/directory");
    ~AcmeClient();
    
    bool initialize();
    AcmeStatus createAccount(const std::string& email);
    AcmeStatus createOrder(const std::vector<std::string>& domains);
    AcmeStatus getChallenges();
    AcmeStatus completeHttpChallenge(const std::string& domain, const std::string& token);
    AcmeStatus completeDnsChallenge(const std::string& domain, const std::string& digest);
    AcmeStatus verifyChallenge(const std::string& authUrl);
    AcmeStatus finalizeOrder(const std::string& csr);
    std::string downloadCertificate();
    
    // Getters for challenge information
    std::map<std::string, std::string> getHttpChallenges() const { return httpChallenges; }
    std::map<std::string, std::string> getDnsChallenges() const { return dnsChallenges; }
    
private:
    std::string directoryUrl;
    std::string accountUrl;
    std::string nonceUrl;
    std::string orderUrl;
    std::string currentOrderUrl;
    std::string finalizeUrl;
    std::string certificateUrl;
    std::string accountKey;
    
    std::map<std::string, std::string> httpChallenges;  // domain -> token
    std::map<std::string, std::string> dnsChallenges;   // domain -> digest
    std::vector<std::string> authUrls;
    
    std::string getNewNonce();
    std::string signRequest(const std::string& payload, const std::string& url, const std::string& nonce);
    std::string base64UrlEncode(const std::string& input);
    std::string computeKeyAuthorization(const std::string& token);
    std::string computeDnsDigest(const std::string& keyAuth);
    std::string makePostRequest(const std::string& url, const std::string& payload);
};

#endif // ACME_CLIENT_HPP 