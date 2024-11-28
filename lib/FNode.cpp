#include <openssl/evp.h>
#include <openssl/pem.h>
#include "FNode.hpp"

void FNode::initializeOpenSSL() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void FNode::generateKeyPair() {
    EVP_PKEY *pkey = EVP_PKEY_new();
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();

    BN_set_word(e, RSA_F4);

    // Generate the RSA key
    if (RSA_generate_key_ex(rsa, 2048, e, NULL) <= 0) {
        BN_free(e);
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to generate RSA key");
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) <= 0) {
        BN_free(e);
        RSA_free(rsa); // Frees rsa if assignment fails
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to assign RSA key to EVP_PKEY");
    }

    BN_free(e);

    FILE *pubKeyFile = fopen("public_key.pem", "wb");
    if (!PEM_write_PUBKEY(pubKeyFile, pkey)) {
        fclose(pubKeyFile);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to write public key to file");
    }
    fclose(pubKeyFile);

    FILE *privKeyFile = fopen("private_key.pem", "wb");
    if (!PEM_write_PrivateKey(privKeyFile, pkey, NULL, NULL, 0, NULL, NULL)) {
        fclose(privKeyFile);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to write private key to file");
    }
    fclose(privKeyFile);

    EVP_PKEY_free(pkey);
}


FNode& FNode::operator=(FNode const& rhs) {
    if (this != &rhs) {
        cleanup();

        try {
            if (rhs.keyPair) {
                EVP_PKEY *pkey = EVP_PKEY_new();
                EVP_PKEY_set1_RSA(pkey, rhs.keyPair);
                keyPair = EVP_PKEY_get1_RSA(pkey);
                EVP_PKEY_free(pkey);
                
                if (!keyPair) {
                    throw std::runtime_error("Failed to copy RSA keyPair");
                }
            }

            peers = rhs.peers;
        } catch (const std::exception& e) {
            std::cerr << "Copy assignment failed: " << e.what() << std::endl;
            cleanup();
            throw;
        }
    }
    return *this;
}


FNode::FNode(FNode const& rhs) {
    try {
        auto temp = std::move(this);
        *this = std::move(rhs);
        delete temp;
    } catch (const std::exception& e) {
        std::cerr << "Initialization failed: " << e.what() << std::endl;
        cleanup();
        throw;
    }
}

FNode::FNode(string addr) {
    try {
        this->address = NodeInfo(addr, 0);
        initializeOpenSSL();
        generateKeyPair();
        std::cout << "P2P Node initialized successfully\n";
    } catch (const std::exception& e) {
        std::cerr << "Initialization failed: " << e.what() << std::endl;
        cleanup();
        throw;
    }
}

ConnectionResult FNode::connectToFAuthority() {
    throw "connectToFAuthority unimplemented";
}

void FNode::addPeer(const std::string& peerAddress) {
    peers.push_back(peerAddress);
    std::cout << "Added peer: " << peerAddress << std::endl;
}

void FNode::connectToPeer(const std::string& peerAddress) {
    struct sockaddr_in peerAddr;
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(55555);
    inet_pton(AF_INET, peerAddress.c_str(), &peerAddr.sin_addr);

    int peerSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(peerSocket, (struct sockaddr*)&peerAddr, sizeof(peerAddr)) < 0) {
        std::cerr << "Failed to connect to peer: " << peerAddress << std::endl;
        close(peerSocket);
        return;
    }

    std::cout << "Connected to peer: " << peerAddress << std::endl;
    // Handle peer connection...
    close(peerSocket);
}

bool FNode::cleanup() {
    try {
        if (keyPair) {
            RSA_free(keyPair);
            keyPair = nullptr;
        }
        if (socketFd >= 0) {
            shutdown(socketFd, SHUT_RDWR);
            close(socketFd);
            socketFd = -1;
        }
        EVP_cleanup();
        ERR_free_strings();
    } catch (const std::exception &e) {
        std::cerr << "Cleanup error: " << e.what() << std::endl;
        return false;
    }
    return true;
}

vector<string> FNode::getPeers()
{
    return peers;
}

int FNode::countPeers() {
    return peers.size();
}

bool FNode::isClean() {
    return (socketFd == -1 && keyPair == nullptr);
}

string FNode::getHostAddr()
{
    return this->address.addr;
}

FNode::~FNode() {
    cleanup();
}

