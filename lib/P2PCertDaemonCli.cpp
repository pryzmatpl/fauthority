#include "P2PCertDaemonCli.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <random>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <json/json.h>

// Global pointer for signal handling
P2PCertDaemonCli* g_daemonInstance = nullptr;

// Signal handler for graceful shutdown
void signalHandler(int signum) {
    if (g_daemonInstance) {
        std::cout << "Received signal " << signum << ", initiating shutdown..." << std::endl;
        g_daemonInstance->run(2, const_cast<char**>(new char*[2]{const_cast<char*>("daemon"), const_cast<char*>("stop")}));
    }
    exit(signum);
}

P2PCertDaemonCli::P2PCertDaemonCli() 
    : node(nullptr), signer(nullptr), nodePort(8443), running(false) {
    
    initCommands();
    
    // Set up signal handling
    g_daemonInstance = this;
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
}

P2PCertDaemonCli::~P2PCertDaemonCli() {
    // Ensure threads are stopped
    if (running.load()) {
        stopNetworkThread();
    }
    
    // Clean up resources
    if (signer) {
        delete signer;
    }
    
    if (node) {
        delete node;
    }
    
    // Reset global instance
    if (g_daemonInstance == this) {
        g_daemonInstance = nullptr;
    }
}

int P2PCertDaemonCli::run(int argc, char** argv) {
    // Load configuration
    loadConfig();
    
    // Default to help if no command specified
    if (argc < 2) {
        return cmdHelp({});
    }
    
    std::string commandStr = argv[1];
    std::vector<std::string> args;
    
    // Extract arguments
    for (int i = 2; i < argc; i++) {
        args.push_back(argv[i]);
    }
    
    // Find and execute command
    auto it = commands.find(commandStr);
    if (it != commands.end()) {
        return it->second(args);
    } else {
        std::cerr << "Unknown command: " << commandStr << std::endl;
        return cmdHelp({});
    }
}

void P2PCertDaemonCli::initCommands() {
    commands["start"] = [this](const std::vector<std::string>& args) {
        return cmdStart(args);
    };
    
    commands["stop"] = [this](const std::vector<std::string>& args) {
        return cmdStop(args);
    };
    
    commands["status"] = [this](const std::vector<std::string>& args) {
        return cmdStatus(args);
    };
    
    commands["list"] = [this](const std::vector<std::string>& args) {
        return cmdList(args);
    };
    
    commands["connect"] = [this](const std::vector<std::string>& args) {
        return cmdConnect(args);
    };
    
    commands["disconnect"] = [this](const std::vector<std::string>& args) {
        return cmdDisconnect(args);
    };
    
    commands["sign"] = [this](const std::vector<std::string>& args) {
        return cmdSign(args);
    };
    
    commands["reject"] = [this](const std::vector<std::string>& args) {
        return cmdReject(args);
    };
    
    commands["help"] = [this](const std::vector<std::string>& args) {
        return cmdHelp(args);
    };
}

int P2PCertDaemonCli::cmdStart(const std::vector<std::string>& args) {
    if (running.load()) {
        std::cout << "P2P Certificate Authority daemon is already running." << std::endl;
        return 0;
    }
    
    // Parse options
    if (hasOption(args, "--node-id")) {
        nodeId = getOptionValue(args, "--node-id");
    } else if (nodeId.empty()) {
        // Generate node ID based on hostname if not specified
        char hostname[1024];
        gethostname(hostname, sizeof(hostname));
        nodeId = std::string(hostname) + ".p2pca";
    }
    
    if (hasOption(args, "--port")) {
        try {
            nodePort = std::stoi(getOptionValue(args, "--port"));
        } catch (const std::exception& e) {
            std::cerr << "Invalid port number. Using default: " << nodePort << std::endl;
        }
    }
    
    if (hasOption(args, "--addr")) {
        nodeAddr = getOptionValue(args, "--addr");
    } else if (nodeAddr.empty()) {
        // Try to get IP address
        FILE* cmdOutput = popen("hostname | awk '{print $1}'", "r");
        if (cmdOutput) {
            char buffer[128];
            if (fgets(buffer, sizeof(buffer), cmdOutput) != nullptr) {
                nodeAddr = buffer;
                // Trim whitespace
                nodeAddr.erase(nodeAddr.find_last_not_of(" \n\r\t") + 1);
            }
            pclose(cmdOutput);
        }
        
        if (nodeAddr.empty()) {
            nodeAddr = "127.0.0.1";  // Default to localhost
        }
    }
    
    std::cout << "Starting P2P Certificate Authority daemon..." << std::endl;
    std::cout << "Node ID: " << nodeId << std::endl;
    std::cout << "Node Address: " << nodeAddr << ":" << nodePort << std::endl;
    
    // Initialize node
    if (!initializeNode()) {
        std::cerr << "Failed to initialize node." << std::endl;
        return 1;
    }
    
    // Start network threads
    startNetworkThread();
    
    // Save configuration
    saveConfig();
    
    std::cout << "P2P Certificate Authority daemon started." << std::endl;
    std::cout << "Use 'status' command to check node status." << std::endl;
    
    return 0;
}

int P2PCertDaemonCli::cmdStop(const std::vector<std::string>& args) {
    if (!running.load()) {
        std::cout << "P2P Certificate Authority daemon is not running." << std::endl;
        return 0;
    }
    
    std::cout << "Stopping P2P Certificate Authority daemon..." << std::endl;
    
    // Stop network threads
    stopNetworkThread();
    
    std::cout << "P2P Certificate Authority daemon stopped." << std::endl;
    
    return 0;
}

int P2PCertDaemonCli::cmdStatus(const std::vector<std::string>& args) {
    if (!running.load()) {
        std::cout << "P2P Certificate Authority daemon is not running." << std::endl;
        return 0;
    }
    
    std::cout << "P2P Certificate Authority daemon status:" << std::endl;
    std::cout << "------------------------------------" << std::endl;
    std::cout << "Node ID: " << nodeId << std::endl;
    std::cout << "Node Address: " << nodeAddr << ":" << nodePort << std::endl;
    std::cout << "Status: " << getStatusString() << std::endl;
    
    // Get connection status
    {
        std::lock_guard<std::mutex> lock(networkMutex);
        std::cout << "Connected Nodes: " << connectedNodes.size() << std::endl;
        if (!connectedNodes.empty()) {
            for (const auto& node : connectedNodes) {
                std::cout << "  - " << node << std::endl;
            }
        }
        
        std::cout << "Pending Requests: " << pendingRequests.size() << std::endl;
        if (!pendingRequests.empty()) {
            for (const auto& req : pendingRequests) {
                std::cout << "  - " << req.first << ": " << req.second << std::endl;
            }
        }
    }
    
    std::cout << "------------------------------------" << std::endl;
    
    return 0;
}

int P2PCertDaemonCli::cmdList(const std::vector<std::string>& args) {
    if (!running.load()) {
        std::cerr << "P2P Certificate Authority daemon is not running." << std::endl;
        return 1;
    }
    
    std::cout << "Known P2P Certificate Authority nodes:" << std::endl;
    std::cout << "------------------------------------" << std::endl;
    
    // List known nodes from the network file
    std::string nodesPath = getNetworkNodesPath();
    std::ifstream nodesFile(nodesPath);
    
    if (nodesFile.is_open()) {
        std::string line;
        while (std::getline(nodesFile, line)) {
            if (!line.empty()) {
                // Check if this node is connected
                bool isConnected = false;
                {
                    std::lock_guard<std::mutex> lock(networkMutex);
                    isConnected = std::find(connectedNodes.begin(), connectedNodes.end(), line) != connectedNodes.end();
                }
                
                std::cout << "  - " << line << (isConnected ? " (connected)" : "") << std::endl;
            }
        }
        nodesFile.close();
    } else {
        std::cout << "  No known nodes. Use 'connect' command to add nodes." << std::endl;
    }
    
    std::cout << "------------------------------------" << std::endl;
    
    return 0;
}

int P2PCertDaemonCli::cmdConnect(const std::vector<std::string>& args) {
    if (!running.load()) {
        std::cerr << "P2P Certificate Authority daemon is not running." << std::endl;
        return 1;
    }
    
    if (args.empty()) {
        std::cerr << "Error: Node address required." << std::endl;
        std::cerr << "Usage: connect <node-address>[:port]" << std::endl;
        return 1;
    }
    
    std::string nodeAddr = args[0];
    
    // Parse address and port
    std::string addr = nodeAddr;
    int port = 8443;  // Default port
    
    size_t colonPos = nodeAddr.find(':');
    if (colonPos != std::string::npos) {
        addr = nodeAddr.substr(0, colonPos);
        try {
            port = std::stoi(nodeAddr.substr(colonPos + 1));
        } catch (const std::exception& e) {
            std::cerr << "Invalid port number. Using default: " << port << std::endl;
        }
    }
    
    std::cout << "Connecting to node: " << addr << ":" << port << "..." << std::endl;
    
    // Simulate connection attempt
    // In a real implementation, this would use node->connectToNode(addr, port)
    
    // Add to known nodes
    std::string nodesPath = getNetworkNodesPath();
    std::ofstream nodesFile(nodesPath, std::ios::app);
    if (nodesFile.is_open()) {
        nodesFile << addr << ":" << port << std::endl;
        nodesFile.close();
    }
    
    // Add to connected nodes
    {
        std::lock_guard<std::mutex> lock(networkMutex);
        std::string fullAddr = addr + ":" + std::to_string(port);
        if (std::find(connectedNodes.begin(), connectedNodes.end(), fullAddr) == connectedNodes.end()) {
            connectedNodes.push_back(fullAddr);
        }
    }
    
    std::cout << "Connected to node: " << addr << ":" << port << std::endl;
    
    return 0;
}

int P2PCertDaemonCli::cmdDisconnect(const std::vector<std::string>& args) {
    if (!running.load()) {
        std::cerr << "P2P Certificate Authority daemon is not running." << std::endl;
        return 1;
    }
    
    if (args.empty()) {
        std::cerr << "Error: Node address required." << std::endl;
        std::cerr << "Usage: disconnect <node-address>[:port]" << std::endl;
        return 1;
    }
    
    std::string nodeAddr = args[0];
    
    std::cout << "Disconnecting from node: " << nodeAddr << "..." << std::endl;
    
    // Simulate disconnection
    // In a real implementation, this would use node->disconnectFromNode(addr, port)
    
    // Remove from connected nodes
    {
        std::lock_guard<std::mutex> lock(networkMutex);
        auto it = std::find(connectedNodes.begin(), connectedNodes.end(), nodeAddr);
        if (it != connectedNodes.end()) {
            connectedNodes.erase(it);
            std::cout << "Disconnected from node: " << nodeAddr << std::endl;
        } else {
            std::cout << "Node not connected: " << nodeAddr << std::endl;
        }
    }
    
    return 0;
}

int P2PCertDaemonCli::cmdSign(const std::vector<std::string>& args) {
    if (!running.load()) {
        std::cerr << "P2P Certificate Authority daemon is not running." << std::endl;
        return 1;
    }
    
    if (args.empty()) {
        std::cerr << "Error: Request ID required." << std::endl;
        std::cerr << "Usage: sign <request-id>" << std::endl;
        return 1;
    }
    
    std::string requestId = args[0];
    
    // Check if request exists
    {
        std::lock_guard<std::mutex> lock(networkMutex);
        auto it = pendingRequests.find(requestId);
        if (it == pendingRequests.end()) {
            std::cerr << "Error: Request not found: " << requestId << std::endl;
            return 1;
        }
        
        // In a real implementation, sign the certificate using the signer
        // signer->signCertificateRequest(it->second);
        
        std::cout << "Signed certificate request: " << requestId << std::endl;
        
        // Remove from pending requests
        pendingRequests.erase(it);
    }
    
    return 0;
}

int P2PCertDaemonCli::cmdReject(const std::vector<std::string>& args) {
    if (!running.load()) {
        std::cerr << "P2P Certificate Authority daemon is not running." << std::endl;
        return 1;
    }
    
    if (args.empty()) {
        std::cerr << "Error: Request ID required." << std::endl;
        std::cerr << "Usage: reject <request-id>" << std::endl;
        return 1;
    }
    
    std::string requestId = args[0];
    
    // Check if request exists
    {
        std::lock_guard<std::mutex> lock(networkMutex);
        auto it = pendingRequests.find(requestId);
        if (it == pendingRequests.end()) {
            std::cerr << "Error: Request not found: " << requestId << std::endl;
            return 1;
        }
        
        // In a real implementation, reject the certificate request
        // signer->rejectCertificateRequest(it->second);
        
        std::cout << "Rejected certificate request: " << requestId << std::endl;
        
        // Remove from pending requests
        pendingRequests.erase(it);
    }
    
    return 0;
}

int P2PCertDaemonCli::cmdHelp(const std::vector<std::string>& args) {
    std::cout << "P2P Certificate Authority Daemon - Usage Guide" << std::endl;
    std::cout << "----------------------------------------------" << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  start           Start the daemon" << std::endl;
    std::cout << "    --node-id     Specify node identifier" << std::endl;
    std::cout << "    --addr        Specify node IP address" << std::endl;
    std::cout << "    --port        Specify node port (default: 8443)" << std::endl;
    std::cout << "  stop            Stop the daemon" << std::endl;
    std::cout << "  status          Show daemon status" << std::endl;
    std::cout << "  list            List known nodes" << std::endl;
    std::cout << "  connect         Connect to a node" << std::endl;
    std::cout << "    <node-addr>   Address of node to connect to" << std::endl;
    std::cout << "  disconnect      Disconnect from a node" << std::endl;
    std::cout << "    <node-addr>   Address of node to disconnect from" << std::endl;
    std::cout << "  sign            Sign a certificate request" << std::endl;
    std::cout << "    <request-id>  ID of request to sign" << std::endl;
    std::cout << "  reject          Reject a certificate request" << std::endl;
    std::cout << "    <request-id>  ID of request to reject" << std::endl;
    std::cout << "  help            Show this help" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  p2pcert-daemon start --node-id ca1.example.com --port 8443" << std::endl;
    std::cout << "  p2pcert-daemon connect ca2.example.com:8443" << std::endl;
    std::cout << "  p2pcert-daemon sign req-1234567890" << std::endl;
    
    return 0;
}

void P2PCertDaemonCli::startNetworkThread() {
    if (running.load()) {
        return;
    }
    
    running.store(true);
    
    // Start network discovery thread
    networkThread = std::thread(&P2PCertDaemonCli::networkDiscoveryLoop, this);
    
    // Start listener thread
    listenerThread = std::thread(&P2PCertDaemonCli::listenerLoop, this);
    
    // Start consensus thread
    consensusThread = std::thread(&P2PCertDaemonCli::consensusLoop, this);
}

void P2PCertDaemonCli::stopNetworkThread() {
    if (!running.load()) {
        return;
    }
    
    running.store(false);
    
    // Wait for threads to finish
    if (networkThread.joinable()) {
        networkThread.join();
    }
    
    if (listenerThread.joinable()) {
        listenerThread.join();
    }
    
    if (consensusThread.joinable()) {
        consensusThread.join();
    }
}

void P2PCertDaemonCli::networkDiscoveryLoop() {
    logMessage("Network discovery thread started");
    
    while (running.load()) {
        // Simulate network discovery logic
        // In a real implementation, this would search for other nodes
        // using DNS, multicast, or other discovery mechanisms
        
        // Simulate finding a new node occasionally
        if (rand() % 10 == 0) {
            int randomPort = 8000 + (rand() % 1000);
            std::string newNode = "192.168.1." + std::to_string(1 + (rand() % 254)) + ":" + std::to_string(randomPort);
            
            {
                std::lock_guard<std::mutex> lock(networkMutex);
                if (std::find(connectedNodes.begin(), connectedNodes.end(), newNode) == connectedNodes.end()) {
                    // In a real implementation, verify the node before adding
                    logMessage("Discovered new node: " + newNode);
                    
                    // For this simulation, we'll only add to known nodes
                    // but not automatically connect
                    
                    // Add to known nodes file
                    std::string nodesPath = getNetworkNodesPath();
                    std::ofstream nodesFile(nodesPath, std::ios::app);
                    if (nodesFile.is_open()) {
                        nodesFile << newNode << std::endl;
                        nodesFile.close();
                    }
                }
            }
        }
        
        // Sleep for a while before next discovery attempt
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    
    logMessage("Network discovery thread stopped");
}

void P2PCertDaemonCli::listenerLoop() {
    logMessage("Listener thread started");
    
    while (running.load()) {
        // Simulate incoming connections and requests
        // In a real implementation, this would listen for incoming TCP connections
        // and handle protocol messages
        
        // Simulate receiving a certificate signing request occasionally
        if (rand() % 20 == 0) {
            // Generate a random request ID
            std::string requestId = "req-";
            for (int i = 0; i < 10; i++) {
                requestId += "0123456789abcdef"[rand() % 16];
            }
            
            // Generate a random domain name
            std::string domain = "";
            int domainParts = 2 + (rand() % 2);
            for (int i = 0; i < domainParts; i++) {
                if (i > 0) {
                    domain += ".";
                }
                
                int partLength = 5 + (rand() % 6);
                for (int j = 0; j < partLength; j++) {
                    domain += "abcdefghijklmnopqrstuvwxyz"[rand() % 26];
                }
            }
            
            domain += (rand() % 2 == 0) ? ".com" : ".org";
            
            // Add to pending requests
            {
                std::lock_guard<std::mutex> lock(networkMutex);
                pendingRequests[requestId] = domain;
                logMessage("Received certificate signing request: " + requestId + " for " + domain);
            }
        }
        
        // Sleep for a while before checking again
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    
    logMessage("Listener thread stopped");
}

void P2PCertDaemonCli::consensusLoop() {
    logMessage("Consensus thread started");
    
    while (running.load()) {
        // Simulate consensus activities
        // In a real implementation, this would participate in the network's
        // consensus process for validating and signing certificates
        
        // Sleep for a while before next consensus round
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
    
    logMessage("Consensus thread stopped");
}

bool P2PCertDaemonCli::initializeNode() {
    // Clean up old node if it exists
    if (node) {
        delete node;
        node = nullptr;
    }
    
    if (signer) {
        delete signer;
        signer = nullptr;
    }

    // Create a new node
    node = new FNode(nodeAddr);
        
    // Create a signer
    signer = new FSigner(node);
    
    return true;
}

bool P2PCertDaemonCli::joinNetwork() {
    if (!node) {
        logMessage("Cannot join network: Node not initialized", true);
        return false;
    }
    
    // Attempt to connect to the P2P network
    // In a real implementation, this would try known bootstrap nodes
    
    // For now, we'll assume it's successful if we have the node object
    return true;
}

bool P2PCertDaemonCli::authenticateNode() {
    if (!node) {
        logMessage("Cannot authenticate: Node not initialized", true);
        return false;
    }
    
    // Authenticate with the network
    AuthStatus status = nodeAuth.authenticateNode(*node, AuthMethod::ProofOfWork);
    
    if (status == AuthStatus::Authenticated) {
        logMessage("Node authenticated with the network");
        return true;
    } else {
        logMessage("Node authentication failed: " + std::to_string(static_cast<int>(status)), true);
        return false;
    }
}

DaemonCommand P2PCertDaemonCli::parseCommand(const std::string& cmd) {
    if (cmd == "start") return DaemonCommand::Start;
    if (cmd == "stop") return DaemonCommand::Stop;
    if (cmd == "status") return DaemonCommand::Status;
    if (cmd == "list") return DaemonCommand::List;
    if (cmd == "connect") return DaemonCommand::Connect;
    if (cmd == "disconnect") return DaemonCommand::Disconnect;
    if (cmd == "sign") return DaemonCommand::Sign;
    if (cmd == "reject") return DaemonCommand::Reject;
    if (cmd == "help") return DaemonCommand::Help;
    
    return DaemonCommand::Unknown;
}

std::string P2PCertDaemonCli::getStatusString() {
    if (running.load()) {
        return "Running";
    } else {
        return "Stopped";
    }
}

bool P2PCertDaemonCli::loadConfig() {
    std::string configPath = getNodeConfigPath();
    
    // Check if file exists
    struct stat buffer;
    if (stat(configPath.c_str(), &buffer) != 0) {
        // Config doesn't exist yet
        return false;
    }
    
    std::ifstream configFile(configPath);
    if (!configFile.is_open()) {
        return false;
    }
    
    Json::Value root;
    Json::CharReaderBuilder builder;
    builder["collectComments"] = false;
    std::string errs;
    
    if (!Json::parseFromStream(builder, configFile, &root, &errs)) {
        logMessage("Error parsing config: " + errs, true);
        configFile.close();
        return false;
    }
    
    configFile.close();
    
    // Extract config values
    if (root.isMember("nodeId")) {
        nodeId = root["nodeId"].asString();
    }
    
    if (root.isMember("nodeAddr")) {
        nodeAddr = root["nodeAddr"].asString();
    }
    
    if (root.isMember("nodePort")) {
        nodePort = root["nodePort"].asInt();
    }
    
    return true;
}

bool P2PCertDaemonCli::saveConfig() {
    // Ensure config directory exists
    std::string configDir = std::filesystem::path(getNodeConfigPath()).parent_path().string();
    
    if (!std::filesystem::exists(configDir)) {
        try {
            std::filesystem::create_directories(configDir);
        } catch (const std::exception& e) {
            logMessage("Error creating config directory: " + std::string(e.what()), true);
            return false;
        }
    }
    
    Json::Value root;
    root["nodeId"] = nodeId;
    root["nodeAddr"] = nodeAddr;
    root["nodePort"] = nodePort;
    
    // Save connected nodes
    Json::Value nodesArray = Json::arrayValue;
    {
        std::lock_guard<std::mutex> lock(networkMutex);
        for (const auto& node : connectedNodes) {
            nodesArray.append(node);
        }
    }
    root["connectedNodes"] = nodesArray;
    
    // Convert to JSON string
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "    "; // Use 4 spaces for indentation
    std::string jsonString = Json::writeString(builder, root);
    
    // Save to file
    std::ofstream configFile(getNodeConfigPath());
    if (!configFile.is_open()) {
        logMessage("Error opening config file for writing", true);
        return false;
    }
    
    configFile << jsonString;
    configFile.close();
    
    return true;
}

bool P2PCertDaemonCli::hasOption(const std::vector<std::string>& args, const std::string& option) {
    return std::find(args.begin(), args.end(), option) != args.end();
}

std::string P2PCertDaemonCli::getOptionValue(const std::vector<std::string>& args, const std::string& option, const std::string& defaultValue) {
    auto it = std::find(args.begin(), args.end(), option);
    if (it != args.end() && it + 1 != args.end()) {
        return *(it + 1);
    }
    return defaultValue;
}

void P2PCertDaemonCli::logMessage(const std::string& message, bool error) {
    // Get current time
    auto now = std::chrono::system_clock::now();
    auto nowTime = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&nowTime), "%Y-%m-%d %H:%M:%S") << " ";
    
    if (error) {
        std::cerr << ss.str() << "[ERROR] " << message << std::endl;
    } else {
        std::cout << ss.str() << "[INFO] " << message << std::endl;
    }
    
    // In a real implementation, this would also log to a file
}

std::string P2PCertDaemonCli::getNodeConfigPath() {
    // Use ~/.p2pca/config.json as the config file
    const char* homeDir = getenv("HOME");
    if (!homeDir) {
        return "/tmp/p2pca/config.json";
    }
    
    return std::string(homeDir) + "/.p2pca/config.json";
}

std::string P2PCertDaemonCli::getNetworkNodesPath() {
    // Use ~/.p2pca/nodes.txt as the nodes file
    const char* homeDir = getenv("HOME");
    if (!homeDir) {
        return "/tmp/p2pca/nodes.txt";
    }
    
    return std::string(homeDir) + "/.p2pca/nodes.txt";
} 