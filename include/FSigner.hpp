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

using namespace std;

class FSigner {
public:
    
private:

    
public:
    FSigner();
    vector<SigningRequest> getSigningRequests(vector<IncomingRequest> incomingConnections);
    SigningStatus signCertificateFromRequest(SigningRequest signingRequest);
    SignedCert getCertUsingSigningStatus(SigningStatus signingStatus);
};

#endif // FSigner
