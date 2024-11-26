#include <iostream>
#include <string>
#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include "DHT.hpp"
#include "ArgParser.hpp"

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

        // Initialize DHT with the provided host address
        std::cout << "Initializing DHT node at: " << hostAddress << std::endl;
        DHT dht(hostAddress);

        // Print initial DHT state
        std::cout << "DHT node initialized:" << std::endl;
        std::cout << "Own Address: " << dht.ownHost() << std::endl;
        std::cout << "Initial peers: " << dht.countHosts() << std::endl;
        std::cout << "Initial lookups: " << dht.countLookups() << std::endl;
        std::cout << "DHT node running. Press Ctrl+C to exit." << std::endl;
        
        while(true) {
            // Per Heartbeat, update the DHT hosts
            // Create a listener thread to check for incoming signing requests
            // Validate whether the cert is signed by peer already, if Not -> Fire off sign request to DHT
            // If Signing was supposed to happen on this host, wait for return request w/ signed cert and give back
            // If signing was requested by other host, sign and send back
            // When cert validation is needed, process the request
            // DHT must have a cache of certificates? 
            // Main loop for handling DHT operations
            // You might want to add periodic tasks here like:
            // - Refreshing peer list
            // - Checking peer health
            // - Processing DHT operations
            
            // Print current DHT status every 5 seconds
            sleep(5);
            std::cout << "Current peers: " << dht.countHosts() 
                      << ", Lookups: " << dht.countLookups() << std::endl;
            
            // Get and print current peers
            auto peers = dht.getPeers();
            if (!peers.empty()) {
                std::cout << "Connected peers:" << std::endl;
                for (const auto& peer : peers) {
                    std::cout << "- " << peer << std::endl;
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}