#include "CertificateTrust.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstdlib>

bool CertificateTrust::installInSystemStore(const Certificate& cert) {
    // Save certificate to temporary file
    std::string tempFile = "/tmp/cert_" + std::to_string(time(nullptr)) + ".pem";
    std::ofstream outFile(tempFile);
    if (!outFile) {
        std::cerr << "Failed to create temporary certificate file" << std::endl;
        return false;
    }
    
    outFile << cert.toPEM();
    outFile.close();
    
    #ifdef _WIN32
    // Windows implementation using certutil
    std::string command = "certutil -addstore -user Root \"" + tempFile + "\"";
    #elif __APPLE__
    // macOS implementation using security tool
    std::string command = "security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain \"" + tempFile + "\"";
    #else
    // Linux implementation (Ubuntu/Debian based)
    std::string command = "sudo cp \"" + tempFile + "\" /usr/local/share/ca-certificates/ && sudo update-ca-certificates";
    #endif
    
    int result = std::system(command.c_str());
    std::remove(tempFile.c_str());
    
    return result == 0;
}

bool CertificateTrust::verifyAgainstSystemStore(const Certificate& cert) {
    // Save certificate to temporary file
    std::string tempFile = "/tmp/cert_to_verify_" + std::to_string(time(nullptr)) + ".pem";
    std::ofstream outFile(tempFile);
    if (!outFile) {
        std::cerr << "Failed to create temporary certificate file" << std::endl;
        return false;
    }
    
    outFile << cert.toPEM();
    outFile.close();
    
    #ifdef _WIN32
    // Windows implementation using certutil
    std::string command = "certutil -verify \"" + tempFile + "\"";
    #elif __APPLE__
    // macOS implementation
    std::string command = "security verify-cert -c \"" + tempFile + "\"";
    #else
    // Linux implementation
    std::string command = "openssl verify \"" + tempFile + "\"";
    #endif
    
    int result = std::system(command.c_str());
    std::remove(tempFile.c_str());
    
    return result == 0;
}

bool CertificateTrust::exportForWebServer(const Certificate& cert, const std::string& path) {
    std::ofstream outFile(path);
    if (!outFile) {
        std::cerr << "Failed to create output file: " << path << std::endl;
        return false;
    }
    
    outFile << cert.toPEM();
    return !outFile.fail();
} 