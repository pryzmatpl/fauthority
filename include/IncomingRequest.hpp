#ifndef INCOMING_REQUEST_HPP
#define INCOMING_REQUEST_HPP

#include <string>
#include <vector>
#include "Certificate.hpp"

enum class RequestType {
    SIGN_CERTIFICATE,
    VERIFY_CERTIFICATE,
    UNKNOWN
};

class IncomingRequest {
public:
    IncomingRequest();
    IncomingRequest(const std::string& rawData, const std::string& clientAddress);
    
    bool parse();
    RequestType getType() const { return type; }
    std::string getClientAddress() const { return clientAddress; }
    Certificate getCertificate() const { return certificate; }
    std::string serialize() const;
    
    static IncomingRequest deserialize(const std::string& data);

private:
    std::string rawData;
    std::string clientAddress;
    RequestType type;
    Certificate certificate;
    bool isParsed;
};

#endif // INCOMING_REQUEST_HPP