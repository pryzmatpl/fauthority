#ifndef NETWORK_CONSENSUS_HPP
#define NETWORK_CONSENSUS_HPP

#include <vector>
#include <string>
#include "SigningRequest.hpp"
#include "FNode.hpp"

enum class ConsensusResult {
    Approved,
    Rejected,
    Insufficient
};

class NetworkConsensus {
public:
    NetworkConsensus(const FNode* node);
    
    ConsensusResult validateRequest(const SigningRequest& request);
    int getMinimumValidationsRequired() const;
    bool hasMinimumPeers() const;
    
private:
    const FNode* node;
    std::vector<std::string> activePeers;
    
    bool requestValidationFromPeer(const std::string& peerAddress, 
                                  const SigningRequest& request);
    void updateActivePeers();
};

#endif // NETWORK_CONSENSUS_HPP 