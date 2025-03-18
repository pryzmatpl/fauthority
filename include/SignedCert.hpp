#ifndef SIGNED_CERT_HPP
#define SIGNED_CERT_HPP

#include <string>
#include <vector>
#include "Certificate.hpp"

class SignedCert {
public:
    SignedCert();
    SignedCert(const Certificate& cert, const std::vector<unsigned char>& signature);
    
    bool verify(const std::string& publicKeyPEM) const;
    bool sendBack();
    std::string serialize() const;
    bool deserialize(const std::string& data);
    
    // Getters
    const Certificate& getCertificate() const { return certificate; }
    const std::vector<unsigned char>& getSignature() const { return signature; }

private:
    Certificate certificate;
    std::vector<unsigned char> signature;
    bool isValid;
};

#endif // SIGNED_CERT_HPP