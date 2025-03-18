#ifndef P2P_CERT_DAEMON_CLI_HPP
#define P2P_CERT_DAEMON_CLI_HPP

#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <functional>
#include "FNode.hpp"
#include "NodeAuthentication.hpp"
#include "FSigner.hpp"
#include "Certificate.hpp"

enum class DaemonCommand {
    Start,
    Stop,
    Status,
    List,
    Connect,
    Disconnect,
    Sign,
    Reject,
    Help,
    Unknown
};

class P2PCertDaemonCli {
public:
    P2PCertDaemonCli();
    ~P2PCertDaemonCli();
    
    int run(int argc, char** argv);
    
private:
    // Node management
    FNode* node;
    NodeAuthentication nodeAuth;
    FSigner* signer;
    std::string nodeId;
    std::string nodeAddr;
    int nodePort;
    
    // Network state
    std::vector<std::string> connectedNodes;
    std::map<std::string, std::string> pendingRequests;
    std::mutex networkMutex;
    
    // Daemon state
    std::atomic<bool> running;
    std::thread networkThread;
    std::thread listenerThread;
    std::thread consensusThread;
    
    // Command handlers
    using CommandFunc = std::function<int(const std::vector<std::string>&)>;
    std::map<std::string, CommandFunc> commands;
    
    // Initialize commands
    void initCommands();
    
    // Command implementation
    int cmdStart(const std::vector<std::string>& args);
    int cmdStop(const std::vector<std::string>& args);
    int cmdStatus(const std::vector<std::string>& args);
    int cmdList(const std::vector<std::string>& args);
    int cmdConnect(const std::vector<std::string>& args);
    int cmdDisconnect(const std::vector<std::string>& args);
    int cmdSign(const std::vector<std::string>& args);
    int cmdReject(const std::vector<std::string>& args);
    int cmdHelp(const std::vector<std::string>& args);
    
    // Network functions
    void startNetworkThread();
    void stopNetworkThread();
    void networkDiscoveryLoop();
    void listenerLoop();
    void consensusLoop();
    
    // Node management
    bool initializeNode();
    bool joinNetwork();
    bool authenticateNode();
    
    // Utility functions
    DaemonCommand parseCommand(const std::string& cmd);
    std::string getStatusString();
    bool loadConfig();
    bool saveConfig();
    bool hasOption(const std::vector<std::string>& args, const std::string& option);
    std::string getOptionValue(const std::vector<std::string>& args, const std::string& option, const std::string& defaultValue = "");
    void logMessage(const std::string& message, bool error = false);
    std::string getNodeConfigPath();
    std::string getNetworkNodesPath();
};

#endif // P2P_CERT_DAEMON_CLI_HPP 