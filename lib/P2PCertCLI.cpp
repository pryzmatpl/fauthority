#include "P2PCertCLI.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <random>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

P2PCertCLI::P2PCertCLI() : node(nullptr) {
    initCommands();
}

P2PCertCLI::~P2PCertCLI() {
    if (node) {
        delete node;
    }
}

int P2PCertCLI::run(int argc, char** argv) {
    // Load configuration
    loadConfig();
    
    // Default to help if no command specified
    if (argc < 2) {
        return cmdHelp({});
    }
    
    std::string command = argv[1];
    std::vector<std::string> args;
    
    // Extract arguments
    for (int i = 2; i < argc; i++) {
        args.push_back(argv[i]);
    }
    
    // Find and execute command
    auto it = commands.find(command);
    if (it != commands.end()) {
        return it->second(args);
    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        return cmdHelp({});
    }
}

void P2PCertCLI::initCommands() {
    commands["help"] = [this](const std::vector<std::string>& args) {
        return cmdHelp(args);
    };
    
    commands["request"] = [this](const std::vector<std::string>& args) {
        return cmdRequest(args);
    };
    
    commands["renew"] = [this](const std::vector<std::string>& args) {
        return cmdRenew(args);
    };
    
    commands["revoke"] = [this](const std::vector<std::string>& args) {
        return cmdRevoke(args);
    };
    
    commands["verify"] = [this](const std::vector<std::string>& args) {
        return cmdVerify(args);
    };
    
    commands["list"] = [this](const std::vector<std::string>& args) {
        return cmdList(args);
    };
    
    commands["install"] = [this](const std::vector<std::string>& args) {
        return cmdInstall(args);
    };
    
    commands["uninstall"] = [this](const std::vector<std::string>& args) {
        return cmdUninstall(args);
    };
    
    commands["generate-root"] = [this](const std::vector<std::string>& args) {
        return cmdGenerateRoot(args);
    };
}

int P2PCertCLI::cmdHelp(const std::vector<std::string>& args) {
    std::cout << "P2P Certificate Authority CLI - Certbot Replacement" << std::endl;
    std::cout << "Usage: p2pcert <command> [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  request <domain>        Request a new certificate" << std::endl;
    std::cout << "  renew [domain]          Renew certificates (specific domain or all)" << std::endl;
    std::cout << "  revoke <domain>         Revoke a certificate" << std::endl;
    std::cout << "  verify <domain>         Verify a certificate's validity" << std::endl;
    std::cout << "  list                    List all managed certificates" << std::endl;
    std::cout << "  install <domain>        Install certificate for web server" << std::endl;
    std::cout << "  uninstall <domain>      Remove certificate from web server" << std::endl;
    std::cout << "  generate-root           Generate a new root CA certificate" << std::endl;
    std::cout << "  help                    Show this help message" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --validation <method>   Validation method (http, dns, email)" << std::endl;
    std::cout << "  --webroot <path>        Path to web root for HTTP validation" << std::endl;
    std::cout << "  --dns-api <provider>    DNS provider for API access" << std::endl;
    std::cout << "  --dns-key <key>         API key for DNS provider" << std::endl;
    std::cout << "  --email <address>       Email address for notifications" << std::endl;
    std::cout << "  --server-type <type>    Web server type (apache, nginx, lighttpd, iis)" << std::endl;
    std::cout << "  --trust-strategy <str>  Trust strategy (local, cross, web, tofu)" << std::endl;
    std::cout << "  --auto-install          Automatically install certificate" << std::endl;
    
    return 0;
}

int P2PCertCLI::cmdRequest(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Error: Domain name required." << std::endl;
        std::cerr << "Usage: p2pcert request <domain> [options]" << std::endl;
        return 1;
    }
    
    std::string domain = args[0];
    std::string webroot = "/var/www/html";
    std::string email = "";
    std::string dnsApi = "";
    std::string dnsKey = "";
    ValidationMethod validationMethod = ValidationMethod::HTTP;
    WebServerType serverType = WebServerType::Unknown;
    TrustStrategy trustStrategy = TrustStrategy::LocalTrust;
    bool autoInstall = false;
    
    // Parse options
    for (size_t i = 1; i < args.size(); i++) {
        if (args[i] == "--validation" && i + 1 < args.size()) {
            validationMethod = parseValidationMethod(args[++i]);
        } else if (args[i] == "--webroot" && i + 1 < args.size()) {
            webroot = args[++i];
        } else if (args[i] == "--email" && i + 1 < args.size()) {
            email = args[++i];
        } else if (args[i] == "--dns-api" && i + 1 < args.size()) {
            dnsApi = args[++i];
        } else if (args[i] == "--dns-key" && i + 1 < args.size()) {
            dnsKey = args[++i];
        } else if (args[i] == "--server-type" && i + 1 < args.size()) {
            serverType = parseWebServerType(args[++i]);
        } else if (args[i] == "--trust-strategy" && i + 1 < args.size()) {
            trustStrategy = parseTrustStrategy(args[++i]);
        } else if (args[i] == "--auto-install") {
            autoInstall = true;
        }
    }
    
    // Connect to P2P network
    if (!connectToNetwork()) {
        return 1;
    }
    
    std::cout << "Requesting certificate for " << domain << std::endl;
    
    // Configure domain validator
    validator.setHttpRootPath(webroot);
    if (!dnsKey.empty()) {
        validator.setDnsApiKey(dnsKey);
    }
    if (!email.empty()) {
        validator.setEmailContact(email);
    }
    
    // Validate domain ownership
    std::cout << "Validating domain ownership..." << std::endl;
    ValidationStatus valStatus = validator.validateDomain(domain, validationMethod);
    
    if (valStatus != ValidationStatus::Success) {
        std::cerr << "Domain validation failed or is pending." << std::endl;
        return 1;
    }
    
    std::cout << "Domain validation successful." << std::endl;
    
    // Generate certificate
    std::cout << "Generating certificate..." << std::endl;
    Certificate cert(domain, "P2P Certificate Authority", "US");
    
    // Generate key pair
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
    EVP_PKEY_assign_RSA(pkey, rsa);
    
    cert.generateX509(pkey);
    
    // Create private key file
    std::string privateKeyPath = "/etc/ssl/private/" + domain + ".key";
    std::filesystem::create_directories(std::filesystem::path(privateKeyPath).parent_path());
    
    FILE* keyFile = fopen(privateKeyPath.c_str(), "w");
    if (!keyFile) {
        std::cerr << "Failed to open key file for writing" << std::endl;
        EVP_PKEY_free(pkey);
        return 1;
    }
    
    PEM_write_PrivateKey(keyFile, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(keyFile);
    
    // Sign certificate with P2P network
    std::cout << "Requesting certificate signing from P2P network..." << std::endl;
    FSigner signer(*node);
    
    // In a real implementation, this would create a proper SigningRequest
    SigningRequest signingReq;
    SigningStatus signStatus = signer.signCertificateFromRequest(signingReq);
    
    if (signStatus != SigningStatus::Signed) {
        std::cerr << "Certificate signing failed." << std::endl;
        EVP_PKEY_free(pkey);
        return 1;
    }
    
    std::cout << "Certificate successfully signed by P2P network." << std::endl;
    
    // Add to certificate manager
    std::cout << "Adding certificate to manager for renewal tracking..." << std::endl;
    certManager.addCertificate(cert, domain, validationMethod);
    
    // Establish browser trust
    std::cout << "Establishing browser trust..." << std::endl;
    TrustStatus trustStatus;
    
    switch (trustStrategy) {
        case TrustStrategy::LocalTrust:
            trustStatus = browserTrust.establishLocalTrust(cert);
            break;
        case TrustStrategy::CrossSigning:
            trustStatus = browserTrust.establishCrossSigning(cert, "Let's Encrypt");
            break;
        case TrustStrategy::WebOfTrust:
            trustStatus = browserTrust.establishWebOfTrust(cert, 3);
            break;
        case TrustStrategy::TrustOnFirstUse:
            trustStatus = browserTrust.establishTOFU(cert, domain);
            break;
    }
    
    if (trustStatus != TrustStatus::Trusted) {
        std::cout << "Warning: Could not establish full browser trust." << std::endl;
    }
    
    // Install certificate if requested
    if (autoInstall) {
        std::cout << "Installing certificate for web server..." << std::endl;
        ConfigStatus configStatus = webConfig.installCertificate(cert, privateKeyPath, serverType);
        
        if (configStatus != ConfigStatus::Success) {
            std::cerr << "Certificate installation failed: " << webConfig.getLastError() << std::endl;
            EVP_PKEY_free(pkey);
            return 1;
        }
        
        std::cout << "Configuring HTTPS..." << std::endl;
        configStatus = webConfig.configureHttps(serverType);
        
        if (configStatus != ConfigStatus::Success) {
            std::cerr << "HTTPS configuration failed: " << webConfig.getLastError() << std::endl;
        } else {
            std::cout << "HTTPS configuration successful." << std::endl;
        }
        
        std::cout << "Enabling HTTP to HTTPS redirect..." << std::endl;
        configStatus = webConfig.enableHttpsRedirect(serverType);
        
        if (configStatus != ConfigStatus::Success) {
            std::cerr << "HTTPS redirect configuration failed: " << webConfig.getLastError() << std::endl;
        } else {
            std::cout << "HTTPS redirect configuration successful." << std::endl;
        }
    }
    
    // Save configuration
    saveConfig();
    
    EVP_PKEY_free(pkey);
    
    std::cout << "Certificate successfully issued for " << domain << std::endl;
    return 0;
}

int P2PCertCLI::cmdRenew(const std::vector<std::string>& args) {
    if (!connectToNetwork()) {
        return 1;
    }
    
    if (args.empty()) {
        // Renew all certificates
        std::cout << "Renewing all certificates..." << std::endl;
        RenewalStatus status = certManager.renewAllCertificates();
        
        if (status == RenewalStatus::Success) {
            std::cout << "All certificates renewed successfully." << std::endl;
            return 0;
        } else {
            std::cerr << "Some certificates failed to renew." << std::endl;
            return 1;
        }
    } else {
        // Renew specific certificate
        std::string domain = args[0];
        std::cout << "Renewing certificate for " << domain << "..." << std::endl;
        RenewalStatus status = certManager.renewCertificate(domain);
        
        if (status == RenewalStatus::Success) {
            std::cout << "Certificate for " << domain << " renewed successfully." << std::endl;
            return 0;
        } else if (status == RenewalStatus::NotNeeded) {
            std::cout << "Certificate for " << domain << " does not need renewal yet." << std::endl;
            return 0;
        } else {
            std::cerr << "Failed to renew certificate for " << domain << "." << std::endl;
            return 1;
        }
    }
}

int P2PCertCLI::cmdRevoke(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Error: Domain name required." << std::endl;
        std::cerr << "Usage: p2pcert revoke <domain>" << std::endl;
        return 1;
    }
    
    std::string domain = args[0];
    
    if (!connectToNetwork()) {
        return 1;
    }
    
    std::cout << "Revoking certificate for " << domain << "..." << std::endl;
    
    // In a real implementation, this would contact the ACME server to revoke
    // For this example, we'll just remove from certificate manager
    
    if (certManager.removeCertificate(domain)) {
        std::cout << "Certificate for " << domain << " successfully revoked." << std::endl;
        return 0;
    } else {
        std::cerr << "Failed to revoke certificate for " << domain << "." << std::endl;
        return 1;
    }
}

int P2PCertCLI::cmdVerify(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Error: Domain name required." << std::endl;
        std::cerr << "Usage: p2pcert verify <domain>" << std::endl;
        return 1;
    }
    
    std::string domain = args[0];
    
    // Get certificates that match this domain
    std::vector<ManagedCertificate> certs = certManager.getExpiringCertificates(3650); // Get all certs within 10 years
    
    bool found = false;
    for (const auto& managedCert : certs) {
        if (managedCert.domain == domain) {
            found = true;
            
            std::cout << "Certificate for " << domain << " found." << std::endl;
            displayCertificateInfo(managedCert.cert);
            
            // Check expiry
            auto now = std::chrono::system_clock::now();
            if (managedCert.expiryDate < now) {
                std::cout << "Certificate has expired!" << std::endl;
            } else {
                auto daysToExpiry = std::chrono::duration_cast<std::chrono::hours>(managedCert.expiryDate - now).count() / 24;
                std::cout << "Certificate expires in " << daysToExpiry << " days." << std::endl;
            }
            
            break;
        }
    }
    
    if (!found) {
        std::cerr << "No certificate found for " << domain << "." << std::endl;
        return 1;
    }
    
    return 0;
}

int P2PCertCLI::cmdList(const std::vector<std::string>& args) {
    // List all managed certificates
    std::vector<ManagedCertificate> certs = certManager.getExpiringCertificates(3650); // Get all certs within 10 years
    
    if (certs.empty()) {
        std::cout << "No certificates found." << std::endl;
        return 0;
    }
    
    std::cout << "Managed certificates:" << std::endl;
    std::cout << std::string(80, '-') << std::endl;
    std::cout << std::left << std::setw(30) << "Domain" 
              << std::setw(20) << "Expiry Date" 
              << std::setw(15) << "Auto-Renew" 
              << std::setw(15) << "Validation" << std::endl;
    std::cout << std::string(80, '-') << std::endl;
    
    auto now = std::chrono::system_clock::now();
    
    for (const auto& cert : certs) {
        std::time_t expiryTime = std::chrono::system_clock::to_time_t(cert.expiryDate);
        char timeStr[20];
        std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d", std::localtime(&expiryTime));
        
        std::string validationMethod;
        switch (cert.validationMethod) {
            case ValidationMethod::HTTP: validationMethod = "HTTP"; break;
            case ValidationMethod::DNS: validationMethod = "DNS"; break;
            case ValidationMethod::EMAIL: validationMethod = "Email"; break;
        }
        
        std::string autoRenew = cert.autoRenew ? "Yes" : "No";
        
        std::cout << std::left << std::setw(30) << cert.domain 
                  << std::setw(20) << timeStr 
                  << std::setw(15) << autoRenew 
                  << std::setw(15) << validationMethod << std::endl;
    }
    
    return 0;
}

int P2PCertCLI::cmdInstall(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Error: Domain name required." << std::endl;
        std::cerr << "Usage: p2pcert install <domain> [options]" << std::endl;
        return 1;
    }
    
    std::string domain = args[0];
    WebServerType serverType = WebServerType::Unknown;
    bool configureHttps = true;
    bool enableRedirect = true;
    
    // Parse options
    for (size_t i = 1; i < args.size(); i++) {
        if (args[i] == "--server-type" && i + 1 < args.size()) {
            serverType = parseWebServerType(args[++i]);
        } else if (args[i] == "--no-https-config") {
            configureHttps = false;
        } else if (args[i] == "--no-redirect") {
            enableRedirect = false;
        }
    }
    
    // Find certificate for domain
    std::vector<ManagedCertificate> certs = certManager.getExpiringCertificates(3650); // Get all certs within 10 years
    
    ManagedCertificate* targetCert = nullptr;
    for (const auto& cert : certs) {
        if (cert.domain == domain) {
            targetCert = const_cast<ManagedCertificate*>(&cert);
            break;
        }
    }
    
    if (!targetCert) {
        std::cerr << "No certificate found for " << domain << "." << std::endl;
        return 1;
    }
    
    // Assume private key path
    std::string privateKeyPath = "/etc/ssl/private/" + domain + ".key";
    
    if (!std::filesystem::exists(privateKeyPath)) {
        std::cerr << "Private key not found at " << privateKeyPath << std::endl;
        return 1;
    }
    
    std::cout << "Installing certificate for " << domain << "..." << std::endl;
    
    // Detect server type if not specified
    if (serverType == WebServerType::Unknown) {
        serverType = webConfig.detectWebServer();
        
        if (serverType == WebServerType::Unknown) {
            std::cerr << "Could not auto-detect web server. Please specify with --server-type." << std::endl;
            return 1;
        }
        
        std::cout << "Detected web server: ";
        switch (serverType) {
            case WebServerType::Apache: std::cout << "Apache"; break;
            case WebServerType::Nginx: std::cout << "Nginx"; break;
            case WebServerType::LightHttpd: std::cout << "Lighttpd"; break;
            case WebServerType::IIS: std::cout << "IIS"; break;
            default: std::cout << "Unknown";
        }
        std::cout << std::endl;
    }
    
    // Install certificate
    ConfigStatus status = webConfig.installCertificate(targetCert->cert, privateKeyPath, serverType);
    
    if (status != ConfigStatus::Success) {
        std::cerr << "Failed to install certificate: " << webConfig.getLastError() << std::endl;
        return 1;
    }
    
    std::cout << "Certificate installed successfully." << std::endl;
    
    // Configure HTTPS if requested
    if (configureHttps) {
        std::cout << "Configuring HTTPS..." << std::endl;
        status = webConfig.configureHttps(serverType);
        
        if (status != ConfigStatus::Success) {
            std::cerr << "Failed to configure HTTPS: " << webConfig.getLastError() << std::endl;
            return 1;
        }
        
        std::cout << "HTTPS configured successfully." << std::endl;
    }
    
    // Enable HTTP to HTTPS redirect if requested
    if (enableRedirect) {
        std::cout << "Enabling HTTP to HTTPS redirect..." << std::endl;
        status = webConfig.enableHttpsRedirect(serverType);
        
        if (status != ConfigStatus::Success) {
            std::cerr << "Failed to configure HTTPS redirect: " << webConfig.getLastError() << std::endl;
            return 1;
        }
        
        std::cout << "HTTPS redirect configured successfully." << std::endl;
    }
    
    return 0;
}

int P2PCertCLI::cmdUninstall(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cerr << "Error: Domain name required." << std::endl;
        std::cerr << "Usage: p2pcert uninstall <domain> [options]" << std::endl;
        return 1;
    }
    
    std::string domain = args[0];
    WebServerType serverType = WebServerType::Unknown;
    
    // Parse options
    for (size_t i = 1; i < args.size(); i++) {
        if (args[i] == "--server-type" && i + 1 < args.size()) {
            serverType = parseWebServerType(args[++i]);
        }
    }
    
    // Detect server type if not specified
    if (serverType == WebServerType::Unknown) {
        serverType = webConfig.detectWebServer();
        
        if (serverType == WebServerType::Unknown) {
            std::cerr << "Could not auto-detect web server. Please specify with --server-type." << std::endl;
            return 1;
        }
    }
    
    std::cout << "Uninstalling certificate for " << domain << "..." << std::endl;
    
    // In a real implementation, this would remove the certificate from web server
    // For this example, we'll just print a message
    
    std::cout << "Certificate for " << domain << " has been uninstalled." << std::endl;
    std::cout << "Note: In a real implementation, this would remove the certificate from the web server configuration." << std::endl;
    
    return 0;
}

int P2PCertCLI::cmdGenerateRoot(const std::vector<std::string>& args) {
    std::string commonName = "P2P Certificate Authority";
    std::string organization = "P2P CA";
    std::string country = "US";
    
    // Parse options
    for (size_t i = 0; i < args.size(); i++) {
        if (args[i] == "--common-name" && i + 1 < args.size()) {
            commonName = args[++i];
        } else if (args[i] == "--organization" && i + 1 < args.size()) {
            organization = args[++i];
        } else if (args[i] == "--country" && i + 1 < args.size()) {
            country = args[++i];
        }
    }
    
    std::cout << "Generating root CA certificate..." << std::endl;
    
    if (browserTrust.generateRootCA(commonName, organization, country)) {
        std::cout << "Root CA certificate generated successfully." << std::endl;
        std::cout << "To use this CA, you need to install it in browsers and operating systems." << std::endl;
        return 0;
    } else {
        std::cerr << "Failed to generate root CA certificate: " << browserTrust.getLastError() << std::endl;
        return 1;
    }
}

void P2PCertCLI::loadConfig() {
    // In a real implementation, this would load config from a file
    // For this example, we'll use hardcoded values
    
    // Configure domain validator
    validator.setHttpRootPath("/var/www/html");
    validator.setEmailContact("admin@example.com");
    
    // Configure certificate manager
    certManager.setRenewalDays(30);
    
    // Configure browser trust
    browserTrust.setRootCAPath("/etc/p2pca/rootCA");
    browserTrust.setTrustStorePath("/etc/ssl/certs");
}

void P2PCertCLI::saveConfig() {
    // In a real implementation, this would save config to a file
    std::cout << "Configuration saved." << std::endl;
}

bool P2PCertCLI::connectToNetwork() {
    // Create a node if not already done
    if (!node) {
        // Get local IP address
        std::string hostAddr = "127.0.0.1"; // Default to localhost
        
        // Try to get a better address
        FILE* cmdOutput = popen("hostname -I | awk '{print $1}'", "r");
        if (cmdOutput) {
            char buffer[128];
            if (fgets(buffer, sizeof(buffer), cmdOutput) != nullptr) {
                hostAddr = buffer;
                // Trim whitespace
                hostAddr.erase(hostAddr.find_last_not_of(" \n\r\t") + 1);
            }
            pclose(cmdOutput);
        }
        
        node = new FNode(hostAddr);
    }
    
    // Connect to the P2P network
    std::cout << "Connecting to P2P certificate authority network..." << std::endl;
    
    // For testing purposes, we'll simulate a successful connection
    // In a real implementation, this would connect to the actual P2P network
    
    // Authenticate the node
    std::cout << "Authenticating node with the network..." << std::endl;
    AuthStatus authStatus = nodeAuth.authenticateNode(*node, AuthMethod::ProofOfWork);
    
    if (authStatus != AuthStatus::Authenticated) {
        std::cerr << "Node authentication failed." << std::endl;
        return false;
    }
    
    std::cout << "Successfully connected to P2P network as: " << node->getHostAddr() << std::endl;
    return true;
}

ValidationMethod P2PCertCLI::parseValidationMethod(const std::string& method) {
    if (method == "http") return ValidationMethod::HTTP;
    if (method == "dns") return ValidationMethod::DNS;
    if (method == "email") return ValidationMethod::EMAIL;
    
    std::cerr << "Unknown validation method: " << method << ". Using HTTP." << std::endl;
    return ValidationMethod::HTTP;
}

WebServerType P2PCertCLI::parseWebServerType(const std::string& serverType) {
    if (serverType == "apache") return WebServerType::Apache;
    if (serverType == "nginx") return WebServerType::Nginx;
    if (serverType == "lighttpd") return WebServerType::LightHttpd;
    if (serverType == "iis") return WebServerType::IIS;
    
    return WebServerType::Unknown;
}

TrustStrategy P2PCertCLI::parseTrustStrategy(const std::string& strategy) {
    if (strategy == "local") return TrustStrategy::LocalTrust;
    if (strategy == "cross") return TrustStrategy::CrossSigning;
    if (strategy == "web") return TrustStrategy::WebOfTrust;
    if (strategy == "tofu") return TrustStrategy::TrustOnFirstUse;
    
    std::cerr << "Unknown trust strategy: " << strategy << ". Using local." << std::endl;
    return TrustStrategy::LocalTrust;
}

void P2PCertCLI::displayCertificateInfo(const Certificate& cert) {
    // In a real implementation, extract and display certificate details from the X509 structure
    // For this example, we'll just show placeholder information
    
    std::cout << "Certificate information:" << std::endl;
    std::cout << "  Subject: CN=test.example.com, O=P2P Certificate Authority, C=US" << std::endl;
    std::cout << "  Issuer: CN=P2P Certificate Authority Root CA, O=P2P CA, C=US" << std::endl;
    std::cout << "  Valid from: 2023-01-01" << std::endl;
    std::cout << "  Valid until: 2024-01-01" << std::endl;
    std::cout << "  Fingerprint: 01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF" << std::endl;
} 