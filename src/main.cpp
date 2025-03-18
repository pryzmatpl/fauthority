#include <iostream>
#include <string>
#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include <signal.h>
#include <atomic>
#include <thread>
#include <chrono>

#include "FNode.hpp"
#include "ArgParser.hpp"
#include "ConnectionResult.hpp"
#include "FServer.hpp"
#include "FSigner.hpp"
#include "ListenerStatus.hpp"
#include "IncomingRequest.hpp"
#include "SignedCert.hpp"

// Global run state
std::atomic<bool> running{true};

void handleSignalInterrupt(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        running.store(false);
    }
}

void connectToFAuthority(FNode& currNode) {
    const int MAX_RETRIES = 5;
    int retryCount = 0;
    ConnectionResult connectionResult;

    do {
        connectionResult = currNode.connectToFAuthority();
        if (connectionResult != ConnectionResult::Connected) {
            std::cout << "Connecting to FAuthority failed. Retry " 
                      << (retryCount + 1) << "/" << MAX_RETRIES << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(5));
            retryCount++;
        }
    } while (connectionResult != ConnectionResult::Connected && retryCount < MAX_RETRIES);

    if (connectionResult != ConnectionResult::Connected) {
        throw std::runtime_error("Failed to connect to FAuthority after multiple attempts.");
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, handleSignalInterrupt);
    signal(SIGTERM, handleSignalInterrupt);

    try {
        ArgParser parser;
        std::string hostAddress = parser.parseArgs(argc, argv);

        std::cout << "Initializing node at: " << hostAddress << std::endl;

        // Initialize a P2P node, generate certs
        FNode currNode(hostAddress);
        std::cout << "FAuthority node initialized:" << std::endl;
        std::cout << "Own Address: " << currNode.getHostAddr() << std::endl;

        connectToFAuthority(currNode);
        std::cout << "Connected to FAuthority" << std::endl;
        std::cout << "Initial peers: " << currNode.countPeers() << std::endl;

        FServer server(currNode);
        FSigner fsigner;

        while (running.load()) {
            ListenerStatus listenStatus = server.listenFAuth();
            std::cout << "FListener status: " << listenStatus << std::endl;

            if (listenStatus == ListenerStatus::Listening) {
                auto incomingConnections = server.acceptIncoming();
                auto incomingSigningRequests = fsigner.getSigningRequests(incomingConnections);

                for (const auto& signingRequest : incomingSigningRequests) {
                    SigningStatus signingStatus = fsigner.signCertificateFromRequest(signingRequest);
                    SignedCert signedCert = fsigner.getCertUsingSigningStatus(signingStatus);
                    signedCert.sendBack();
                }
            }

            std::this_thread::sleep_for(std::chrono::seconds(5));
            server.refresh();
        }

        server.shutdown();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}