#include "SigningRequest.hpp"

SigningRequest::SigningRequest() : isRequestValid(false) {}

SigningRequest::SigningRequest(const IncomingRequest& request) 
    : requesterAddress(request.getClientAddress()),
      isRequestValid(false) {
    
    if (validateRequest(request)) {
        certificate = request.getCertificate();
        isRequestValid = true;
    }
}

bool SigningRequest::isValid() const {
    return isRequestValid;
}

bool SigningRequest::validateRequest(const IncomingRequest& request) {
    // Basic validation
    if (request.getType() != RequestType::SIGN_CERTIFICATE) {
        return false;
    }
    
    if (request.getClientAddress().empty()) {
        return false;
    }
    
    // Additional validation could be added here
    // For example:
    // - Check if the requester is authorized
    // - Validate certificate format
    // - Check rate limiting
    
    return true;
} 