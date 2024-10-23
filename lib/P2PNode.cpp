#include "P2PNode.hpp"

void P2PNode::initializeOpenSSL() {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void P2PNode::generateKeyPair() {
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

void P2PNode::initializeNetwork() {
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
        throw std::runtime_error("Failed to bind socket");
    }

    // Start listening
    if (listen(socketFd, 5) < 0) {
        throw std::runtime_error("Failed to listen on socket");
    }
}

P2PNode::P2PNode() {
    try {
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

void P2PNode::addPeer(const std::string& peerAddress) {
    peers.push_back(peerAddress);
    std::cout << "Added peer: " << peerAddress << std::endl;
}

void P2PNode::connectToPeer(const std::string& peerAddress) {
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

void P2PNode::cleanup() {
    if (keyPair) {
        RSA_free(keyPair);
    }
    if (socketFd >= 0) {
        close(socketFd);
    }
    EVP_cleanup();
    ERR_free_strings();
}

P2PNode::~P2PNode() {
    cleanup();
}
