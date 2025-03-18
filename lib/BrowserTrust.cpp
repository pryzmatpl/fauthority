#include "BrowserTrust.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

BrowserTrust::BrowserTrust() 
    : rootCAPath("/etc/p2pca/rootCA"),
      trustStorePath("/etc/ssl/certs") {
}

TrustStatus BrowserTrust::establishLocalTrust(const Certificate& cert) {
    if (installInLocalTrustStore(cert)) {
        return TrustStatus::Trusted;
    } else {
        return TrustStatus::Error;
    }
}

TrustStatus BrowserTrust::establishCrossSigning(const Certificate& cert, const std::string& caName) {
    if (requestCrossSigning(cert, caName)) {
        return TrustStatus::Trusted;
    } else {
        return TrustStatus::Error;
    }
}

TrustStatus BrowserTrust::establishWebOfTrust(const Certificate& cert, int requiredSignatures) {
    int signatures = countTrustedSignatures(cert);
    
    std::cout << "Certificate has " << signatures << " trusted signatures" << std::endl;
    
    if (signatures >= requiredSignatures) {
        return TrustStatus::Trusted;
    } else if (signatures > 0) {
        return TrustStatus::Unknown;
    } else {
        return TrustStatus::Untrusted;
    }
}

TrustStatus BrowserTrust::establishTOFU(const Certificate& cert, const std::string& domain) {
    if (!hasRecordedCertificate(domain)) {
        if (recordFirstUse(cert, domain)) {
            return TrustStatus::Trusted;
        } else {
            return TrustStatus::Error;
        }
    } else {
        if (certificateMatchesRecord(cert, domain)) {
            return TrustStatus::Trusted;
        } else {
            return TrustStatus::Untrusted;
        }
    }
}

bool BrowserTrust::generateRootCA(const std::string& commonName, 
                                 const std::string& organization,
                                 const std::string& country) {
    // Create directories if they don't exist
    if (!std::filesystem::exists(rootCAPath)) {
        std::filesystem::create_directories(rootCAPath);
    }
    
    // Generate key pair
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_generate_key(4096, RSA_F4, nullptr, nullptr);
    EVP_PKEY_assign_RSA(pkey, rsa);
    
    // Create root certificate
    Certificate rootCert(commonName, organization, country);
    rootCert.generateX509(pkey);
    
    // Self-sign the root certificate
    if (!rootCert.sign(pkey)) {
        EVP_PKEY_free(pkey);
        lastError = "Failed to sign root certificate";
        return false;
    }
    
    // Save private key
    std::string keyPath = rootCAPath + "/ca.key";
    FILE* keyFile = fopen(keyPath.c_str(), "w");
    if (!keyFile) {
        EVP_PKEY_free(pkey);
        lastError = "Failed to open key file for writing";
        return false;
    }
    
    PEM_write_PrivateKey(keyFile, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(keyFile);
    
    // Save certificate
    std::string certPath = rootCAPath + "/ca.crt";
    std::ofstream certFile(certPath);
    if (!certFile) {
        EVP_PKEY_free(pkey);
        lastError = "Failed to open certificate file for writing";
        return false;
    }
    
    certFile << rootCert.toPEM();
    certFile.close();
    
    EVP_PKEY_free(pkey);
    
    std::cout << "Root CA generated:" << std::endl;
    std::cout << "Private key: " << keyPath << std::endl;
    std::cout << "Certificate: " << certPath << std::endl;
    
    // Try to install in local trust store
    if (installInLocalTrustStore(rootCert)) {
        std::cout << "Root CA installed in local trust store" << std::endl;
    } else {
        std::cout << "Failed to install Root CA in local trust store" << std::endl;
        std::cout << "You may need to install it manually" << std::endl;
    }
    
    return true;
}

bool BrowserTrust::installInLocalTrustStore(const Certificate& cert) {
    // Save certificate to temporary file
    std::string tempFile = "/tmp/cert_" + std::to_string(time(nullptr)) + ".pem";
    std::ofstream outFile(tempFile);
    if (!outFile) {
        lastError = "Failed to create temporary certificate file";
        return false;
    }
    
    outFile << cert.toPEM();
    outFile.close();
    
    // Different commands for different platforms
    std::string command;
    bool result = false;
    
    #ifdef _WIN32
    // Windows implementation
    command = "certutil -addstore -f \"ROOT\" \"" + tempFile + "\"";
    result = std::system(command.c_str()) == 0;
    #elif __APPLE__
    // macOS implementation
    command = "security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \"" + tempFile + "\"";
    result = std::system(command.c_str()) == 0;
    #else
    // Linux implementation
    command = "sudo cp \"" + tempFile + "\" \"" + trustStorePath + "/p2pca-root.crt\" && "
             + "sudo update-ca-certificates";
    result = std::system(command.c_str()) == 0;
    #endif
    
    // Clean up
    std::remove(tempFile.c_str());
    
    if (!result) {
        lastError = "Failed to install certificate in trust store";
    }
    
    return result;
}

bool BrowserTrust::removeFromLocalTrustStore(const Certificate& cert) {
    // Different commands for different platforms
    std::string command;
    bool result = false;
    
    #ifdef _WIN32
    // Windows implementation
    // Need certificate hash or serial number
    command = "certutil -delstore \"ROOT\" \"P2P Certificate Authority\"";
    result = std::system(command.c_str()) == 0;
    #elif __APPLE__
    // macOS implementation
    command = "security delete-certificate -c \"P2P Certificate Authority\" /Library/Keychains/System.keychain";
    result = std::system(command.c_str()) == 0;
    #else
    // Linux implementation
    command = "sudo rm \"" + trustStorePath + "/p2pca-root.crt\" && "
             + "sudo update-ca-certificates --fresh";
    result = std::system(command.c_str()) == 0;
    #endif
    
    if (!result) {
        lastError = "Failed to remove certificate from trust store";
    }
    
    return result;
}

bool BrowserTrust::requestCrossSigning(const Certificate& cert, const std::string& caName) {
    // In a real implementation, this would involve:
    // 1. Generating a CSR
    // 2. Contacting a commercial CA
    // 3. Going through their validation process
    // 4. Receiving the cross-signed certificate
    
    std::cout << "Requesting cross-signing from " << caName << std::endl;
    std::cout << "This is a placeholder for the actual cross-signing process" << std::endl;
    
    // For this example, we'll simulate cross-signing
    return false;
}

int BrowserTrust::countTrustedSignatures(const Certificate& cert) {
    // In a real implementation, this would check X.509 extensions
    // for signatures from trusted parties.
    
    // For this example, we'll simulate counting signatures
    int count = 0;
    
    for (const auto& signatory : trustedSignatories) {
        // Simulate a 50% chance that this signatory has signed the cert
        if (rand() % 2 == 0) {
            count++;
        }
    }
    
    return count;
}

bool BrowserTrust::addSignatureToWebOfTrust(const Certificate& cert, const std::string& signatory) {
    // In a real implementation, this would add a signature to the certificate
    // or record the signature in a distributed database
    
    std::cout << "Adding signature from " << signatory << " to web of trust" << std::endl;
    
    // For this example, we'll just add to trusted signatories
    trustedSignatories.push_back(signatory);
    
    return true;
}

bool BrowserTrust::recordFirstUse(const Certificate& cert, const std::string& domain) {
    // Create directory if it doesn't exist
    std::string tofuDir = rootCAPath + "/tofu";
    if (!std::filesystem::exists(tofuDir)) {
        std::filesystem::create_directories(tofuDir);
    }
    
    // Save certificate hash for the domain
    std::string domainFile = tofuDir + "/" + domain;
    std::ofstream file(domainFile);
    if (!file) {
        lastError = "Failed to create TOFU record file";
        return false;
    }
    
    // In a real implementation, save a hash or fingerprint
    file << cert.toPEM();
    file.close();
    
    std::cout << "Recorded first use of certificate for " << domain << std::endl;
    return true;
}

bool BrowserTrust::hasRecordedCertificate(const std::string& domain) {
    std::string domainFile = rootCAPath + "/tofu/" + domain;
    return std::filesystem::exists(domainFile);
}

bool BrowserTrust::certificateMatchesRecord(const Certificate& cert, const std::string& domain) {
    std::string domainFile = rootCAPath + "/tofu/" + domain;
    
    std::ifstream file(domainFile);
    if (!file) {
        return false;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();
    
    // In a real implementation, compare hashes or fingerprints
    return buffer.str() == cert.toPEM();
} 