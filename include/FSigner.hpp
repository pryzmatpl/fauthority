#ifndef FSIGNER_HPP
#define FSIGNER_HPP

#include <string>
#include <map>
#include <vector>
#include <functional>
#include <cstdint>
#include <algorithm>
#include <memory>
#include <chrono>
#include <random>
#include <iostream>
#include <unordered_map>
#include "FNode.hpp"
#include "SigningRequest.hpp"
#include "IncomingRequest.hpp"
#include "SignedCert.hpp"
#include "SigningStatus.hpp"

class NetworkConsensus;

class FSigner {
private:
    const FNode* node = nullptr;
    NetworkConsensus* consensus = nullptr;
    SignedCert* lastSignedCert = nullptr;
    
public:
    FSigner();
    FSigner(const FNode* node);
    ~FSigner();
    
    std::vector<SigningRequest> getSigningRequests(std::vector<IncomingRequest> requests);
    SigningStatus signCertificateFromRequest(const SigningRequest& request);
    SignedCert getCertUsingSigningStatus(SigningStatus status);
};

#endif // FSIGNER_HPP
