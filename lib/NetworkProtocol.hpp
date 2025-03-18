#ifndef NETWORK_PROTOCOL_HPP
#define NETWORK_PROTOCOL_HPP

#include <string>
#include <vector>
#include <map>
#include <json/json.h>

// Message types
enum class MessageType {
    HELLO,
    NODE_LIST,
    CERTIFICATE_REQUEST,
    CERTIFICATE_RESPONSE,
    CERTIFICATE_VERIFICATION,
    CONSENSUS_VOTE,
    STATUS,
    ERROR
};

struct Message {
    MessageType type;
    std::string nodeId;
    std::string data;
    std::map<std::string, std::string> metadata;
    
    // Convert to JSON string
    std::string toJson() const {
        Json::Value root;
        root["type"] = static_cast<int>(type);
        root["nodeId"] = nodeId;
        root["data"] = data;
        
        Json::Value metaValue;
        for (const auto& kv : metadata) {
            metaValue[kv.first] = kv.second;
        }
        root["metadata"] = metaValue;
        
        Json::StreamWriterBuilder builder;
        return Json::writeString(builder, root);
    }
    
    // Parse from JSON string
    static Message fromJson(const std::string& jsonStr) {
        Message msg;
        
        Json::Value root;
        Json::CharReaderBuilder builder;
        std::string errs;
        std::istringstream jsonStream(jsonStr);
        
        if (!Json::parseFromStream(builder, jsonStream, &root, &errs)) {
            msg.type = MessageType::ERROR;
            msg.data = "Invalid JSON: " + errs;
            return msg;
        }
        
        msg.type = static_cast<MessageType>(root["type"].asInt());
        msg.nodeId = root["nodeId"].asString();
        msg.data = root["data"].asString();
        
        Json::Value metaValue = root["metadata"];
        for (const auto& key : metaValue.getMemberNames()) {
            msg.metadata[key] = metaValue[key].asString();
        }
        
        return msg;
    }
};

// Basic network protocol functions for the P2P certificate authority
class NetworkProtocol {
public:
    // Send a message to a node
    static bool sendMessage(const std::string& nodeAddr, int port, const Message& msg);
    
    // Receive a message
    static Message receiveMessage(int socket);
    
    // Create a message
    static Message createMessage(MessageType type, const std::string& nodeId, const std::string& data);
    
    // Process a received message
    static Message processMessage(const Message& msg, const std::string& ownNodeId);
};

#endif // NETWORK_PROTOCOL_HPP 