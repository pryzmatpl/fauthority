#include "FServer.hpp"

using namespace std;

FServer::FServer() {}
FServer::FServer(const std::string& hostAddress) : host(hostAddress) {}

void FServer::initializeNetwork() {    
    // Create socket
    auto socketFd = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFd < 0) {
        throw std::runtime_error("Failed to create socket");
    }

    int opt = 1;
    setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(55555);

    if (bind(socketFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        char* message;
        asprintf(&message, "Failed to bind socket %d", socketFd);
        throw std::runtime_error(message);
    }

    if (listen(socketFd, 5) < 0) {
        throw std::runtime_error("Failed to listen on socket");
    }
}

ListenerStatus FServer::listenFAuth() {
    return ListenerStatus::Unavailable;
}

FServer::FServer(const FNode& node) {
    std::cout << "FServer initialized with an FNode." << std::endl;
}

vector<IncomingRequest> FServer::acceptIncoming() {
    std::cout << "FServer accepting incoming connections." << std::endl;
}

bool FServer::refresh() {
    std::cout << "FServer refreshing state." << std::endl;
    return false;
}

void FServer::shutdown() {
    // Placeholder implementation
    std::cout << "FServer shutting down." << std::endl;
}

std::string FServer::ownHost() const {
    std::cout << "FServer::ownHost called." << std::endl;
    return "127.0.0.1"; // Default value for testing
}

void FServer::addPeer(const std::string& peerAddress) {
    std::cout << "FServer::addPeer called with " << peerAddress << "." << std::endl;
    peers.push_back(peerAddress);
}

bool FServer::removePeer(const std::string& peerAddress) {
    std::cout << "FServer::removePeer called with " << peerAddress << "." << std::endl;
    auto it = std::find(peers.begin(), peers.end(), peerAddress);
    if (it != peers.end()) {
        peers.erase(it);
        return true;
    }
    return false;
}

int FServer::countHosts() const {
    std::cout << "FServer::countHosts called." << std::endl;
    return peers.size(); 
}

int FServer::countLookups() const {
    std::cout << "FServer::countLookups called." << std::endl;
    return lookupCount; 
}

std::vector<std::string> FServer::getPeers() const {
    std::cout << "FServer::getPeers called." << std::endl;
    return peers;
}