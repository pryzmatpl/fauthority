#include <iostream>
#include "P2PNode.hpp"

int main() {
    try {
        P2PNode node;
        
        // Add some example peers
        node.addPeer("192.168.1.100");
        node.addPeer("192.168.1.101");
        
        // Try connecting to peers
        node.connectToPeer("192.168.1.100");
        
        std::cout << "P2P node running. Press Ctrl+C to exit." << std::endl;
        while(true) {
            // Main loop for handling connections
            sleep(1);
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}