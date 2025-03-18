#ifndef CERTIFICATE_HPP
#define CERTIFICATE_HPP

#include <string>
#include <vector>
#include <openssl/x509.h>
#include <openssl/pem.h>

class Certificate {
public:
    Certificate();
    Certificate(const std::string& commonName, 
                const std::string& organization,
                const std::string& country);
    ~Certificate();

    bool generateX509(EVP_PKEY* publicKey);
    bool sign(EVP_PKEY* signingKey);
    bool verify(EVP_PKEY* publicKey) const;
    std::string toPEM() const;
    bool fromPEM(const std::string& pemData);

private:
    X509* cert;
    void initialize();
    void cleanup();
};

#endif // CERTIFICATE_HPP 