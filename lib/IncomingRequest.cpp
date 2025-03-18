#include "IncomingRequest.hpp"
#include <sstream>
#include <iostream>

IncomingRequest::IncomingRequest() 
    : type(RequestType::UNKNOWN), isParsed(false) {}

IncomingRequest::IncomingRequest(const std::string& data, const std::string& client) 
    : rawData(data), clientAddress(client), type(RequestType::UNKNOWN), isParsed(false) {}

bool IncomingRequest::parse() {
    if (isParsed) return true;
    if (rawData.empty()) return false;

    try {
        std::istringstream ss(rawData);
        std::string requestTypeStr;
        
        // First line contains request type
        std::getline(ss, requestTypeStr);
        
        if (requestTypeStr == "SIGN") {
            type = RequestType::SIGN_CERTIFICATE;
        } else if (requestTypeStr == "VERIFY") {
            type = RequestType::VERIFY_CERTIFICATE;
        } else {
            type = RequestType::UNKNOWN;
            return false;
        }

        // Rest of the data is the certificate in PEM format
        std::string certData;
        std::string line;
        while (std::getline(ss, line)) {
            certData += line + "\n";
        }

        if (!certificate.fromPEM(certData)) {
            return false;
        }

        isParsed = true;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error parsing request: " << e.what() << std::endl;
        return false;
    }
}

std::string IncomingRequest::serialize() const {
    std::ostringstream ss;
    
    // Serialize request type
    switch (type) {
        case RequestType::SIGN_CERTIFICATE:
            ss << "SIGN\n";
            break;
        case RequestType::VERIFY_CERTIFICATE:
            ss << "VERIFY\n";
            break;
        default:
            ss << "UNKNOWN\n";
    }
    
    // Serialize certificate
    ss << certificate.toPEM();
    
    return ss.str();
}

IncomingRequest IncomingRequest::deserialize(const std::string& data) {
    IncomingRequest request(data, "");
    request.parse();
    return request;
} 