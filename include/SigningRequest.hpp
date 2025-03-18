#ifndef SIGNING_REQUEST_HPP
#define SIGNING_REQUEST_HPP

#include "IncomingRequest.hpp"
#include "Certificate.hpp"
#include <string>

class SigningRequest {
public:
    SigningRequest();
    SigningRequest(const IncomingRequest& request);
    
    bool isValid() const;
    Certificate getCertificate() const { return certificate; }
    std::string getRequesterAddress() const { return requesterAddress; }
    
    // For testing purposes
    void setValid(bool valid) { isRequestValid = valid; }

private:
    Certificate certificate;
    std::string requesterAddress;
    bool isRequestValid;
    
    bool validateRequest(const IncomingRequest& request);
};

#endif // SIGNING_REQUEST_HPP