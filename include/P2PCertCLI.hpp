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
    
    // Helper methods
    void loadConfig();
    void saveConfig();
    bool connectToNetwork();
    ValidationMethod parseValidationMethod(const std::string& method);
    WebServerType parseWebServerType(const std::string& serverType);
    TrustStrategy parseTrustStrategy(const std::string& strategy);
    void displayCertificateInfo(const Certificate& cert);
};

#endif // P2P_CERT_CLI_HPP 