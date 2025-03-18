#include "FSigner.hpp"
#include "NetworkConsensus.hpp"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace std;

// Default constructor
FSigner::FSigner() {
    std::cout << "FSigner created." << std::endl;
}

// Constructor with node reference
FSigner::FSigner(const FNode& node) : node(node), consensus(new NetworkConsensus(node)) {
    std::cout << "FSigner created with node reference." << std::endl;
}

FSigner::~FSigner() {
    delete consensus;
}

// Get signing requests
std::vector<SigningRequest> FSigner::getSigningRequests(std::vector<IncomingRequest> requests) {
    std::cout << "FSigner fetching signing requests." << std::endl;
    std::vector<SigningRequest> signingRequests;
    
    for (const auto& request : requests) {
        SigningRequest signingRequest(request);
        if (signingRequest.isValid()) {
            signingRequests.push_back(signingRequest);
        }
    }
    
    return signingRequests;
}

// Sign a certificate from a request
SigningStatus FSigner::signCertificateFromRequest(const SigningRequest& request) {
    std::cout << "FSigner signing certificate from request." << std::endl;

    // Skip consensus check if not initialized with a node
    if (consensus) {
        ConsensusResult consensusResult = consensus->validateRequest(request);
        
        if (consensusResult == ConsensusResult::Insufficient) {
            std::cerr << "Not enough peers for consensus" << std::endl;
            return SigningStatus::NetworkError;
        }
        
        if (consensusResult == ConsensusResult::Rejected) {
            std::cerr << "Request rejected by network consensus" << std::endl;
            return SigningStatus::Rejected;
        }
    }

    // Load the private key
    FILE* privateKeyFile = fopen("private_key.pem", "r");
    if (!privateKeyFile) {
        std::cerr << "Failed to open private key file." << std::endl;
        return SigningStatus::Error;
    }

    EVP_PKEY* privateKey = PEM_read_PrivateKey(privateKeyFile, nullptr, nullptr, nullptr);
    fclose(privateKeyFile);

    if (!privateKey) {
        std::cerr << "Failed to read private key." << std::endl;
        return SigningStatus::Error;
    }

    // Get certificate to sign
    Certificate cert = request.getCertificate();
    
    // Sign the certificate
    if (!cert.sign(privateKey)) {
        std::cerr << "Failed to sign certificate" << std::endl;
        EVP_PKEY_free(privateKey);
        return SigningStatus::Error;
    }

    EVP_PKEY_free(privateKey);
    
    // Store signed certificate for later retrieval
    lastSignedCert = new SignedCert(cert, std::vector<unsigned char>()); // Empty signature for now
    
    std::cout << "Certificate signed successfully." << std::endl;
    return SigningStatus::Signed;
}

// Get certificates using signing status
SignedCert FSigner::getCertUsingSigningStatus(SigningStatus status) {
    std::cout << "FSigner fetching certificates with status: " << static_cast<int>(status) << std::endl;
    
    if (status == SigningStatus::Signed && lastSignedCert) {
        return *lastSignedCert;
    }
    
    return SignedCert(); // Return an empty SignedCert for now
}

