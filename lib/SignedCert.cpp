#include "SignedCert.hpp"
#include <sstream>
#include <iomanip>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

SignedCert::SignedCert() : isValid(false) {}

SignedCert::SignedCert(const Certificate& cert, const std::vector<unsigned char>& sig)
    : certificate(cert), signature(sig), isValid(true) {}

bool SignedCert::verify(const std::string& publicKeyPEM) const {
    if (!isValid) return false;

    BIO* bio = BIO_new_mem_buf(publicKeyPEM.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) return false;

    bool result = certificate.verify(pkey);
    EVP_PKEY_free(pkey);
    return result;
}

bool SignedCert::sendBack() {
    // Implement network sending logic here
    // For now, just serialize the certificate
    std::string serialized = serialize();
    return !serialized.empty();
}

std::string SignedCert::serialize() const {
    std::stringstream ss;
    
    // Serialize certificate
    ss << certificate.toPEM() << "\n";
    
    // Serialize signature
    for (unsigned char byte : signature) {
        ss << std::hex << std::setw(2) << std::setfill('0') 
           << static_cast<int>(byte);
    }
    
    return ss.str();
}

bool SignedCert::deserialize(const std::string& data) {
    size_t pos = data.find("\n");
    if (pos == std::string::npos) return false;

    // Deserialize certificate
    std::string certPEM = data.substr(0, pos);
    if (!certificate.fromPEM(certPEM)) return false;

    // Deserialize signature
    std::string sigHex = data.substr(pos + 1);
    signature.clear();
    for (size_t i = 0; i < sigHex.length(); i += 2) {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << sigHex.substr(i, 2);
        ss >> byte;
        signature.push_back(static_cast<unsigned char>(byte));
    }

    isValid = true;
    return true;
}
