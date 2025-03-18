#ifndef P2P_CERT_CLI_HPP
#define P2P_CERT_CLI_HPP

#include <string>
#include <vector>
#include <map>
#include <functional>
#include "AcmeClient.hpp"
#include "DomainValidator.hpp"
#include "CertificateManager.hpp"
#include "WebServerConfigurator.hpp"
#include "NodeAuthentication.hpp"
#include "BrowserTrust.hpp"
#include "FNode.hpp"
#include "FSigner.hpp"

class P2PCertCLI {
public:
    P2PCertCLI();
    ~P2PCertCLI();
    
    int run(int argc, char** argv);
    
private:
    AcmeClient acmeClient;
    DomainValidator validator;
    CertificateManager certManager;
    WebServerConfigurator webConfig;
    NodeAuthentication nodeAuth;
    BrowserTrust browserTrust;
    FNode* node;
    
    // Command handlers
    using CommandFunc = std::function<int(const std::vector<std::string>&)>;
    std::map<std::string, CommandFunc> commands;
    
    // Initialize commands
    void initCommands();
    
    // Command implementations
    int cmdHelp(const std::vector<std::string>& args);
    int cmdRequest(const std::vector<std::string>& args);
    int cmdRenew(const std::vector<std::string>& args);
    int cmdRevoke(const std::vector<std::string>& args);
    int cmdVerify(const std::vector<std::string>& args);
    int cmdList(const std::vector<std::string>& args);
    int cmdInstall(const std::vector<std::string>& args);
    int cmdUninstall(const std::vector<std::string>& args);
    int cmdGenerateRoot(const std::vector<std::string>& args);
    int cmdNetwork(const std::vector<std::string>& args);

    // Helper methods
    void loadConfig();
    void saveConfig();
    bool connectToNetwork();
    ValidationMethod parseValidationMethod(const std::string& method);
    WebServerType parseWebServerType(const std::string& serverType);
    TrustStrategy parseTrustStrategy(const std::string& strategy);
    void displayCertificateInfo(const Certificate& cert);
    
    bool hasOption(const std::vector<std::string>& args, const std::string& option) {
        return std::find(args.begin(), args.end(), option) != args.end();
    }

    std::string getOptionValue(const std::vector<std::string>& args, const std::string& option, const std::string& defaultValue = "") {
        auto it = std::find(args.begin(), args.end(), option);
        if (it != args.end() && it + 1 != args.end()) {
            return *(it + 1);
        }
        return defaultValue;
    }
    // New P2P-specific methods and properties
    std::string p2pNodeAddress;
    int p2pNodePort;
    
    // Connect to P2P network
    bool connectToP2PNode(const std::string& nodeAddr);
    bool disconnectFromP2PNode();
    
    // P2P certificate operations
    bool submitCertificateToP2PNetwork(const Certificate& cert);
    bool renewCertificateViaP2P(const std::string& domain);
    bool verifyCertificateWithP2P(const Certificate& cert);
};

#endif // P2P_CERT_CLI_HPP 