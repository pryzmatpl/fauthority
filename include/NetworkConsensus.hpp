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
    NetworkConsensus(const FNode* node, int port = 55555);
    
    ConsensusResult validateRequest(const SigningRequest& request);
    int getMinimumValidationsRequired() const;
    bool hasMinimumPeers() const;
    void setPort(int port) { peerPort = port; }
    int getPort() const { return peerPort; }
    
private:
    const FNode* node;
    std::vector<std::string> activePeers;
    int peerPort;
    
    bool requestValidationFromPeer(const std::string& peerAddress, 
                                  const SigningRequest& request);
    void updateActivePeers();
};

#endif // NETWORK_CONSENSUS_HPP 