#include "Certificate.hpp"
#include <stdexcept>
#include <openssl/err.h>
#include <sstream>

Certificate::Certificate() : cert(nullptr) {
    initialize();
}

Certificate::Certificate(const std::string& commonName,
                       const std::string& organization,
                       const std::string& country) : cert(nullptr) {
    initialize();
    
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, 
        (const unsigned char*)commonName.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
        (const unsigned char*)organization.c_str(), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
        (const unsigned char*)country.c_str(), -1, -1, 0);
}

Certificate::~Certificate() {
    cleanup();
}

void Certificate::initialize() {
    cert = X509_new();
    if (!cert) {
        throw std::runtime_error("Failed to create X509 certificate");
    }

    // Set version to X509v3
    X509_set_version(cert, 2);

    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); // Valid for 1 year
}

void Certificate::cleanup() {
    if (cert) {
        X509_free(cert);
        cert = nullptr;
    }
}

bool Certificate::generateX509(EVP_PKEY* publicKey) {
    if (!cert || !publicKey) return false;

    X509_set_pubkey(cert, publicKey);
    return true;
}

bool Certificate::sign(EVP_PKEY* signingKey) {
    if (!cert || !signingKey) return false;

    if (!X509_sign(cert, signingKey, EVP_sha256())) {
        return false;
    }
    return true;
}

bool Certificate::verify(EVP_PKEY* publicKey) const {
    if (!cert || !publicKey) return false;
    
    return X509_verify(cert, publicKey) == 1;
}

std::string Certificate::toPEM() const {
    if (!cert) return "";

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    
    char* data;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, len);
    
    BIO_free(bio);
    return result;
}

bool Certificate::fromPEM(const std::string& pemData) {
    cleanup();
    
    BIO* bio = BIO_new_mem_buf(pemData.c_str(), -1);
    cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    return cert != nullptr;
} 