#include "FServer.hpp"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>

using namespace std;

FServer::FServer() : lookupCount(0) {}

FServer::FServer(FNode& node) : host(node.getHostAddr()) {
    initializeNetwork();
}

void FServer::initializeNetwork() {
    // Create socket
    socketFd = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFd < 0) {
        throw std::runtime_error("Failed to create socket");
    }

    int opt = 1;
    setsockopt(socketFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    serverAddr.sin_port = htons(55555); // Port number

    if (bind(socketFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        throw std::runtime_error("Failed to bind socket");
    }

    if (listen(socketFd, 5) < 0) {
        throw std::runtime_error("Failed to listen on socket");
    }

    std::cout << "Server initialized and listening on port 55555." << std::endl;
}

ListenerStatus FServer::listenFAuth() {
    // Check if the server is ready to accept connections
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(socketFd, &readfds);

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    int activity = select(socketFd + 1, &readfds, nullptr, nullptr, &timeout);
    if (activity < 0) {
        std::cerr << "Select error" << std::endl;
        return ListenerStatus::Unavailable;
    }

    if (FD_ISSET(socketFd, &readfds)) {
        return ListenerStatus::Listening; // Ready to accept connections
    }

    return ListenerStatus::Deaf; // No activity
}

vector<IncomingRequest> FServer::acceptIncoming() {
    struct sockaddr_in clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    int newSocket = accept(socketFd, (struct sockaddr*)&clientAddr, &addrLen);
    if (newSocket < 0) {
        std::cerr << "Failed to accept connection" << std::endl;
        return {};
    }

    std::cout << "Accepted a new connection." << std::endl;

    // Here you would read the incoming request from the socket
    // For simplicity, we will return a dummy IncomingRequest
    close(newSocket); // Close the connection after accepting
    return std::vector<IncomingRequest>(1); // Return a vector with one dummy request
}

bool FServer::refresh() {
    // In a real implementation, you might check the status of connections or peers
    std::cout << "Refreshing server state..." << std::endl;
    return true; // Assume refresh is successful
}

void FServer::shutdown() {
    close(socketFd);
    std::cout << "Server shutdown." << std::endl;
}

std::string FServer::ownHost() const {
    return host; // Return the host address
}

void FServer::addPeer(const std::string& peerAddress) {
    std::cout << "Adding peer: " << peerAddress << std::endl;
    peers.push_back(peerAddress);
}

bool FServer::removePeer(const std::string& peerAddress) {
    auto it = std::remove(peers.begin(), peers.end(), peerAddress);
    if (it != peers.end()) {
        peers.erase(it, peers.end());
        std::cout << "Removed peer: " << peerAddress << std::endl;
        return true;
    }
    return false;
}

int FServer::countHosts() const {
    return peers.size();
}

int FServer::countLookups() const {
    return lookupCount; // Return the number of lookups (mocked for now)
}

std::vector<std::string> FServer::getPeers() const {
    return peers; // Return the list of peers
}