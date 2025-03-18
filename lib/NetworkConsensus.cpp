#include "NetworkConsensus.hpp"
#include <iostream>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

NetworkConsensus::NetworkConsensus(const FNode& n) : node(n) {
    updateActivePeers();
}

ConsensusResult NetworkConsensus::validateRequest(const SigningRequest& request) {
    if (!hasMinimumPeers()) {
        std::cerr << "Not enough peers for consensus" << std::endl;
        return ConsensusResult::Insufficient;
    }
    
    int validations = 0;
    int minimumValidations = getMinimumValidationsRequired();
    
    for (const auto& peer : activePeers) {
        if (requestValidationFromPeer(peer, request)) {
            validations++;
        }
        
        if (validations >= minimumValidations) {
            return ConsensusResult::Approved;
        }
    }
    
    if (validations < minimumValidations) {
        return ConsensusResult::Rejected;
    }
    
    return ConsensusResult::Approved;
}

int NetworkConsensus::getMinimumValidationsRequired() const {
    // Require majority of peers to validate (including self)
    return std::max(1, static_cast<int>(activePeers.size() / 2));
}

bool NetworkConsensus::hasMinimumPeers() const {
    // Need at least one other peer (2 nodes total)
    return activePeers.size() >= 1;
}

bool NetworkConsensus::requestValidationFromPeer(
    const std::string& peerAddress, const SigningRequest& request) {
    
    // Create socket for peer communication
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to create socket for peer validation" << std::endl;
        return false;
    }
    
    // Set up the peer address
    struct sockaddr_in peerAddr;
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(55555); // Use same port as server
    
    if (inet_pton(AF_INET, peerAddress.c_str(), &peerAddr.sin_addr) <= 0) {
        std::cerr << "Invalid peer address: " << peerAddress << std::endl;
        close(sock);
        return false;
    }
    
    // Connect to peer
    if (connect(sock, (struct sockaddr*)&peerAddr, sizeof(peerAddr)) < 0) {
        std::cerr << "Failed to connect to peer: " << peerAddress << std::endl;
        close(sock);
        return false;
    }
    
    // Prepare validation request message
    std::string message = "VALIDATE\n";
    message += request.getCertificate().toPEM();
    
    // Send request
    if (send(sock, message.c_str(), message.length(), 0) < 0) {
        std::cerr << "Failed to send validation request to peer" << std::endl;
        close(sock);
        return false;
    }
    
    // Receive response
    char buffer[1024] = {0};
    int bytesRead = recv(sock, buffer, sizeof(buffer)-1, 0);
    close(sock);
    
    if (bytesRead < 0) {
        std::cerr << "Failed to receive validation response from peer" << std::endl;
        return false;
    }
    
    // Check response (simple OK/REJECT protocol)
    std::string response(buffer);
    return response.substr(0, 2) == "OK";
}

void NetworkConsensus::updateActivePeers() {
    activePeers = node.getPeers();
} 