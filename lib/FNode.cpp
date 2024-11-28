#include "FNode.hpp"

void FNode::initializeOpenSSL() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void FNode::generateKeyPair() {
    // Generate 2048-bit RSA key pair
    keyPair = RSA_new();
    BIGNUM* bne = BN_new();
    BN_set_word(bne, RSA_F4);

    RSA_generate_key_ex(keyPair, 2048, bne, nullptr);
    BN_free(bne);

    // Save public key to file
    FILE* pubKeyFile = fopen("public_key.pem", "wb");
    PEM_write_RSAPublicKey(pubKeyFile, keyPair);
    fclose(pubKeyFile);

    // Save private key to file
    FILE* privKeyFile = fopen("private_key.pem", "wb");
    PEM_write_RSAPrivateKey(privKeyFile, keyPair, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(privKeyFile);
}

void FNode::initializeNetwork() {    
    // Create socket
    socketFd = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFd < 0) {
        throw std::runtime_error("Failed to create socket");
    }

    // Set socket options for reuse
    int opt = 1;
    setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Configure server address
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    // Bind socket
    if (bind(socketFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        char* message;
        asprintf(&message, "Failed to bind socket %d", socketFd);
        throw std::runtime_error(message);
    }

    // Start listening
    if (listen(socketFd, 5) < 0) {
        throw std::runtime_error("Failed to listen on socket");
    }
}

FNode& FNode::operator=(FNode const& rhs) {
    if (this != &rhs) { 
        // Clean up current resources
        cleanup();

        try {
            // Deep copy of keyPair
            if (rhs.keyPair) {
                // Generate a new RSA key pair and copy the content from rhs.keyPair
                keyPair = RSA_new();
                if (!keyPair) {
                    throw std::runtime_error("Failed to allocate RSA keyPair");
                }

                // Copy the key components (deep copy)
                // The specific OpenSSL functions to deep copy key pairs may vary, but generally it involves duplicating the RSA components.
                if (!RSA_set0_key(keyPair,
                                 BN_dup(RSA_get0_n(rhs.keyPair)),    // Copy modulus n
                                 BN_dup(RSA_get0_e(rhs.keyPair)),    // Copy public exponent e
                                 BN_dup(RSA_get0_d(rhs.keyPair)))) { // Copy private exponent d (if available)
                    throw std::runtime_error("Failed to copy RSA keyPair");
                }
            }

            // Copy non-pointer members
            peers = rhs.peers;
            PORT = rhs.PORT;

            // Re-initialize network settings
            initializeNetwork();
        } catch (const std::exception& e) {
            std::cerr << "Copy assignment failed: " << e.what() << std::endl;
            cleanup();
            throw; // Rethrow to let the caller handle the failure
        }
    }

    return *this; // Return *this to allow chaining of assignment
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
        initializeNetwork();
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
    peerAddr.sin_port = htons(PORT);
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
        }
        if (socketFd >= 0) {
            shutdown(socketFd, SHUT_RDWR);
            close(socketFd);
        }
        EVP_cleanup();
        ERR_free_strings();
    } catch (std::exception &e) {
        auto clsName = typeid(FNode).name();
        std::cerr << clsName << " " << e.what() << "\n";
    }

    return true;
}

int FNode::countPeers() {
    return peers.size();
}

bool FNode::isClean() {
    int error_code;
    socklen_t error_code_size = sizeof(error_code);
    try {        
        std::cout << error_code << "\n";
        return (socketFd == -1);
    } catch (std::exception &e) {
        std::cerr << e.what() << "\n";
    }
}

string FNode::getHostAddr()
{
    return this->address.addr;
}

FNode::~FNode() {
    cleanup();
}


