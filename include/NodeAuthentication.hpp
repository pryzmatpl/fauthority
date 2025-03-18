#ifndef NODE_AUTHENTICATION_HPP
#define NODE_AUTHENTICATION_HPP

#include <string>
#include <vector>
#include <map>
#include <functional>
#include "FNode.hpp"

enum class AuthMethod {
    ProofOfWork,
    ProofOfStake,
    SocialGraph,
    WebOfTrust
};

enum class AuthStatus {
    Authenticated,
    Rejected,
    Pending,
    Error
};

class NodeAuthentication {
public:
    NodeAuthentication();
    
    // Node authentication
    AuthStatus authenticateNode(const FNode& node, AuthMethod method);
    bool verifyNodeAuthenticity(const std::string& nodeId);
    
    // Proof of Work methods
    void setWorkDifficulty(int difficulty) { workDifficulty = difficulty; }
    AuthStatus performProofOfWork(const FNode& node);
    bool verifyProofOfWork(const std::string& nodeId, const std::string& proof);
    
    // Proof of Stake methods
    void setMinimumStake(int stake) { minimumStake = stake; }
    AuthStatus performProofOfStake(const FNode& node);
    bool verifyProofOfStake(const std::string& nodeId, int stake);
    
    // Social Graph methods
    void addTrustedNode(const std::string& nodeId) { trustedNodes.push_back(nodeId); }
    AuthStatus verifySocialTrust(const FNode& node);
    
    // Web of Trust methods
    void addTrustRelation(const std::string& trustor, const std::string& trustee);
    int calculateTrustScore(const std::string& nodeId);
    AuthStatus verifyWebOfTrust(const FNode& node);
    
private:
    int workDifficulty;           // For Proof of Work
    int minimumStake;             // For Proof of Stake
    std::vector<std::string> trustedNodes; // For direct trust
    std::map<std::string, std::vector<std::string>> trustGraph; // For Web of Trust
    
    std::string calculateChallenge(const std::string& nodeId);
    std::string calculateHash(const std::string& data);
};

#endif // NODE_AUTHENTICATION_HPP 