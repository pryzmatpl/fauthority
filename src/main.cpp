#include <iostream>
#include <string>
#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include <signal.h>
#include <atomic>

#include "FNode.hpp"
#include "ArgParser.hpp"
#include "ConnectionResult.hpp"
#include "FServer.hpp"
#include "FSigner.hpp"
#include "ListenerStatus.hpp"
#include "IncomingRequest.hpp"
#include "SignedCert.hpp"

// Global run state (Hate on me, haters)
std::atomic<bool> running{true};

void handleSignalInterrupt(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        running.store(false);
    }
}

int main(int argc, char* argv[]) {
    signal(SIGINT, handleSignalInterrupt);
    signal(SIGTERM, handleSignalInterrupt);

    try {
        auto parser = ArgParser();
        // Parse command line arguments
        std::string hostAddress;

        try {
            hostAddress = parser.parseArgs(argc, argv);
        } catch (const std::exception& e) {
            parser.printUsage(argv[0]);
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }

        std::cout << "Initializing node at: " << hostAddress << std::endl;

        // First, initialize a P2P node, generate certs
        auto currNode = FNode(hostAddress);

        // Print initial DHT state
        std::cout << "FAuthority node initialized:" << std::endl;
        std::cout << "Own Address: " << currNode.getHostAddr() << std::endl;
        std::cout << "FAuthority node running. Press Ctrl+C to exit." << std::endl;
        std::cout << "Connecting to FAuthority..." << std::endl;
        
        ConnectionResult connectionResult = currNode.connectToFAuthority();

        const int MAX_RETRIES = 5;
        int retryCount = 0;
        while (connectionResult != ConnectionResult::Connected && retryCount < MAX_RETRIES) {
            std::cout << "Connecting to FAuthority failed. Retry " 
                      << (retryCount + 1) << "/" << MAX_RETRIES << std::endl;
            sleep(5);
            connectionResult = currNode.connectToFAuthority();
            retryCount++;
        }

        std::cout << "Connected to FAuthority" << std::endl;
        std::cout << "Initial peers: " << currNode.countPeers() << std::endl;
        std::cout << "Starting server ..." << std::endl;
        FServer server(currNode);
        FSigner fsigner = FSigner();

        while(running.load()) {
            ListenerStatus listenStatus = server.listen();
            ListenerStatus listenStatus = server.listen();

            std::cout << "FListener status: " <<  listenStatus << std::endl;

            if (listenStatus == ListenerStatus::Listening) {
                vector<IncomingRequest> incomingConnections = server.acceptIncoming();
                
                vector<SigningRequest> incomingSigningRequests = fsigner.getSigningRequests(incomingConnections);

                for(SigningRequest signingRequest : incomingSigningRequests) {
                    SigningStatus signingStatus = fsigner.signCertificateFromRequest(signingRequest);
                    SignedCert signedCert = fsigner.getCertUsingSigningStatus(signingStatus);
                    signedCert.sendBack();
                }
            }

            // Wait 5 s
            sleep(5);

            server.refresh();
        }

        server.shutdown();
        currNode.disconnect();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}