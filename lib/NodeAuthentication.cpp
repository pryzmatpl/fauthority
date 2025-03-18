#include "NodeAuthentication.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <random>
#include <ctime>
#include <algorithm>
#include <openssl/sha.h>
#include <queue>
#include <set>

NodeAuthentication::NodeAuthentication() 
    : workDifficulty(4), minimumStake(100) {
}

AuthStatus NodeAuthentication::authenticateNode(const FNode& node, AuthMethod method) {
    std::string nodeId = node.getHostAddr(); // Using host address as node ID for simplicity
    
    switch (method) {
        case AuthMethod::ProofOfWork:
            return performProofOfWork(node);
        case AuthMethod::ProofOfStake:
            return performProofOfStake(node);
        case AuthMethod::SocialGraph:
            return verifySocialTrust(node);
        case AuthMethod::WebOfTrust:
            return verifyWebOfTrust(node);
        default:
            return AuthStatus::Error;
    }
}

bool NodeAuthentication::verifyNodeAuthenticity(const std::string& nodeId) {
    // This is a simplified implementation that assumes a node is authentic
    // if it was previously authenticated by any method
    
    // In a real implementation, you would check against a database or registry
    // of authenticated nodes with expiration times, etc.
    
    return true; // For this example, always return true
}

// Proof of Work methods
AuthStatus NodeAuthentication::performProofOfWork(const FNode& node) {
    std::string nodeId = node.getHostAddr();
    std::string challenge = calculateChallenge(nodeId);
    
    std::cout << "Node " << nodeId << " performing proof of work..." << std::endl;
    
    // In a real implementation, the node would solve this challenge
    // For this example, we'll simulate the process
    
    // Generate a random nonce and check if it solves the challenge
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 1000000);
    
    for (int i = 0; i < 10; i++) { // Limited attempts for the example
        int nonce = distrib(gen);
        std::string attempt = challenge + std::to_string(nonce);
        std::string hash = calculateHash(attempt);
        
        // Check if hash meets difficulty requirement
        bool valid = true;
        for (int j = 0; j < workDifficulty; j++) {
            if (hash[j] != '0') {
                valid = false;
                break;
            }
        }
        
        if (valid) {
            std::cout << "Proof of work succeeded for node " << nodeId << std::endl;
            return AuthStatus::Authenticated;
        }
    }
    
    std::cout << "Proof of work failed for node " << nodeId << std::endl;
    return AuthStatus::Rejected;
}

bool NodeAuthentication::verifyProofOfWork(const std::string& nodeId, const std::string& proof) {
    std::string challenge = calculateChallenge(nodeId);
    std::string hash = calculateHash(challenge + proof);
    
    // Check if hash meets difficulty requirement
    for (int i = 0; i < workDifficulty; i++) {
        if (hash[i] != '0') {
            return false;
        }
    }
    
    return true;
}

// Proof of Stake methods
AuthStatus NodeAuthentication::performProofOfStake(const FNode& node) {
    std::string nodeId = node.getHostAddr();
    
    // In a real implementation, you would check the node's stake in the network
    // For this example, we'll simulate a random stake
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 200);
    
    int stake = distrib(gen);
    
    if (stake >= minimumStake) {
        std::cout << "Node " << nodeId << " has sufficient stake: " << stake << std::endl;
        return AuthStatus::Authenticated;
    } else {
        std::cout << "Node " << nodeId << " has insufficient stake: " << stake << std::endl;
        return AuthStatus::Rejected;
    }
}

bool NodeAuthentication::verifyProofOfStake(const std::string& nodeId, int stake) {
    return stake >= minimumStake;
}

// Social Graph methods
AuthStatus NodeAuthentication::verifySocialTrust(const FNode& node) {
    std::string nodeId = node.getHostAddr();
    
    // Check if the node is directly trusted
    if (std::find(trustedNodes.begin(), trustedNodes.end(), nodeId) != trustedNodes.end()) {
        std::cout << "Node " << nodeId << " is directly trusted" << std::endl;
        return AuthStatus::Authenticated;
    }
    
    // Check if the node is vouched for by at least one trusted node
    for (const auto& trustedNode : trustedNodes) {
        // In a real implementation, you would check if trustedNode has vouched for nodeId
        // For this example, we'll simulate a random vouch
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(0, 1);
        
        if (distrib(gen) == 1) {
            std::cout << "Node " << nodeId << " is vouched for by trusted node " << trustedNode << std::endl;
            return AuthStatus::Authenticated;
        }
    }
    
    std::cout << "Node " << nodeId << " is not socially trusted" << std::endl;
    return AuthStatus::Rejected;
}

// Web of Trust methods
void NodeAuthentication::addTrustRelation(const std::string& trustor, const std::string& trustee) {
    trustGraph[trustor].push_back(trustee);
}

int NodeAuthentication::calculateTrustScore(const std::string& nodeId) {
    // Implementation of a simplified PageRank-like algorithm
    
    // Initialize trust scores
    std::map<std::string, double> trustScores;
    for (const auto& entry : trustGraph) {
        trustScores[entry.first] = 1.0;
    }
    
    // Iterative calculation (simplified)
    for (int i = 0; i < 10; i++) { // 10 iterations
        std::map<std::string, double> newScores;
        
        for (const auto& entry : trustGraph) {
            const std::string& source = entry.first;
            const std::vector<std::string>& targets = entry.second;
            
            if (!targets.empty()) {
                double sharePerTarget = trustScores[source] / targets.size();
                for (const std::string& target : targets) {
                    newScores[target] += sharePerTarget;
                }
            }
        }
        
        // Update scores
        for (auto& entry : newScores) {
            // Damping factor of 0.85
            trustScores[entry.first] = 0.15 + 0.85 * entry.second;
        }
    }
    
    // Convert to int score
    return static_cast<int>(trustScores[nodeId] * 100);
}

AuthStatus NodeAuthentication::verifyWebOfTrust(const FNode& node) {
    std::string nodeId = node.getHostAddr();
    
    int trustScore = calculateTrustScore(nodeId);
    std::cout << "Node " << nodeId << " has trust score: " << trustScore << std::endl;
    
    // Threshold for authentication
    if (trustScore >= 50) {
        return AuthStatus::Authenticated;
    } else {
        return AuthStatus::Rejected;
    }
}

std::string NodeAuthentication::calculateChallenge(const std::string& nodeId) {
    // Create a challenge based on nodeId and current time
    std::time_t currentTime = std::time(nullptr);
    return nodeId + std::to_string(currentTime);
}

std::string NodeAuthentication::calculateHash(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.length());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    return ss.str();
} 