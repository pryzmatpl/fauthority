#include "P2PCertCLI.hpp"
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) {
    try {
        // Initialize OpenSSL
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        
        // Create and run the CLI
        P2PCertCLI cli;
        int result = cli.run(argc, argv);
        
        // Clean up OpenSSL
        EVP_cleanup();
        ERR_free_strings();
        
        return result;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown error occurred" << std::endl;
        return 1;
    }
}