#include <iostream>
#include <string>
#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include "FNode.hpp"
#include "ArgParser.hpp"
#include "ConnectionResult.hpp"
#include "FServer.hpp"
#include "FSigner.hpp"
#include "ListenerStatus.hpp"
#include "IncomingRequest.hpp"
#include "SignedCert.hpp"

int main(int argc, char* argv[]) {
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
        
        while (connectionResult != ConnectionResult::Connected) {
            std::cout << "Connecting to FAuthority failed. Retrying in 5s" << std::endl;
            sleep(5);
        }

        std::cout << "Connected to FAuthority" << std::endl;
        std::cout << "Initial peers: " << currNode.countPeers() << std::endl;
        std::cout << "Starting server ..." << std::endl;
        FServer server(currNode);
        FSigner fsigner = FSigner();

        while(true) {
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
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}