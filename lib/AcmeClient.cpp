#include "AcmeClient.hpp"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <curl/curl.h>
#include <json/json.h>
#include <iostream>
#include <sstream>

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t newLength = size * nmemb;
    try {
        s->append((char*)contents, newLength);
        return newLength;
    } catch(std::bad_alloc& e) {
        return 0;
    }
}

AcmeClient::AcmeClient(const std::string& dirUrl) 
    : directoryUrl(dirUrl) {
    curl_global_init(CURL_GLOBAL_ALL);
}

AcmeClient::~AcmeClient() {
    curl_global_cleanup();
}

bool AcmeClient::initialize() {
    // Fetch directory URLs
    std::string response = makePostRequest(directoryUrl, "");
    
    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(response, root)) {
        std::cerr << "Failed to parse directory response" << std::endl;
        return false;
    }
    
    nonceUrl = root["newNonce"].asString();
    accountUrl = root["newAccount"].asString();
    orderUrl = root["newOrder"].asString();
    
    // Generate account key if not already done
    if (accountKey.empty()) {
        EVP_PKEY* pkey = EVP_PKEY_new();
        RSA* rsa = RSA_generate_key(2048, RSA_F4, nullptr, nullptr);
        EVP_PKEY_assign_RSA(pkey, rsa);
        
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(bio, pkey);
        
        char* data;
        long len = BIO_get_mem_data(bio, &data);
        accountKey = std::string(data, len);
        
        BIO_free(bio);
        EVP_PKEY_free(pkey);
    }
    
    return true;
}

AcmeStatus AcmeClient::createAccount(const std::string& email) {
    std::string nonce = getNewNonce();
    
    Json::Value payload;
    payload["termsOfServiceAgreed"] = true;
    
    Json::Value contact(Json::arrayValue);
    contact.append("mailto:" + email);
    payload["contact"] = contact;
    
    Json::FastWriter writer;
    std::string payloadStr = writer.write(payload);
    
    std::string response = signRequest(payloadStr, accountUrl, nonce);
    
    // Parse response to get account URL
    // In a real implementation, store this for future use
    
    return AcmeStatus::Success;
}

AcmeStatus AcmeClient::createOrder(const std::vector<std::string>& domains) {
    std::string nonce = getNewNonce();
    
    Json::Value payload;
    Json::Value identifiers(Json::arrayValue);
    
    for (const std::string& domain : domains) {
        Json::Value identifier;
        identifier["type"] = "dns";
        identifier["value"] = domain;
        identifiers.append(identifier);
    }
    
    payload["identifiers"] = identifiers;
    
    Json::FastWriter writer;
    std::string payloadStr = writer.write(payload);
    
    std::string response = signRequest(payloadStr, orderUrl, nonce);
    
    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(response, root)) {
        std::cerr << "Failed to parse order response" << std::endl;
        return AcmeStatus::OrderFailed;
    }
    
    currentOrderUrl = root["url"].asString();
    finalizeUrl = root["finalize"].asString();
    
    // Extract authorization URLs
    authUrls.clear();
    const Json::Value& auths = root["authorizations"];
    for (unsigned int i = 0; i < auths.size(); i++) {
        authUrls.push_back(auths[i].asString());
    }
    
    return AcmeStatus::Success;
}

AcmeStatus AcmeClient::getChallenges() {
    httpChallenges.clear();
    dnsChallenges.clear();
    
    for (const std::string& authUrl : authUrls) {
        std::string nonce = getNewNonce();
        std::string response = signRequest("", authUrl, nonce);
        
        Json::Value root;
        Json::Reader reader;
        if (!reader.parse(response, root)) {
            std::cerr << "Failed to parse auth response" << std::endl;
            return AcmeStatus::AuthorizationFailed;
        }
        
        std::string domain = root["identifier"]["value"].asString();
        
        // Extract HTTP and DNS challenges
        const Json::Value& challenges = root["challenges"];
        for (unsigned int i = 0; i < challenges.size(); i++) {
            std::string type = challenges[i]["type"].asString();
            std::string token = challenges[i]["token"].asString();
            
            if (type == "http-01") {
                httpChallenges[domain] = token;
            } else if (type == "dns-01") {
                std::string keyAuth = computeKeyAuthorization(token);
                std::string digest = computeDnsDigest(keyAuth);
                dnsChallenges[domain] = digest;
            }
        }
    }
    
    return AcmeStatus::PendingChallenge;
}

AcmeStatus AcmeClient::completeHttpChallenge(const std::string& domain, const std::string& token) {
    // In a real implementation, this would create the challenge file
    // For this example, we'll just log it
    std::string keyAuth = computeKeyAuthorization(token);
    std::cout << "HTTP challenge for " << domain << ": " << std::endl;
    std::cout << "Create file at: /.well-known/acme-challenge/" << token << std::endl;
    std::cout << "With content: " << keyAuth << std::endl;
    
    return AcmeStatus::Success;
}

AcmeStatus AcmeClient::completeDnsChallenge(const std::string& domain, const std::string& digest) {
    // In a real implementation, this would create the DNS TXT record
    // For this example, we'll just log it
    std::cout << "DNS challenge for " << domain << ": " << std::endl;
    std::cout << "Create TXT record for: _acme-challenge." << domain << std::endl;
    std::cout << "With content: " << digest << std::endl;
    
    return AcmeStatus::Success;
}

AcmeStatus AcmeClient::verifyChallenge(const std::string& authUrl) {
    // Notify the server that the challenge is ready
    std::string nonce = getNewNonce();
    
    Json::Value payload;
    payload["status"] = "ready";
    
    Json::FastWriter writer;
    std::string payloadStr = writer.write(payload);
    
    std::string response = signRequest(payloadStr, authUrl, nonce);
    
    // In a real implementation, poll the status until it's valid or invalid
    
    return AcmeStatus::Success;
}

AcmeStatus AcmeClient::finalizeOrder(const std::string& csr) {
    std::string nonce = getNewNonce();
    
    Json::Value payload;
    payload["csr"] = base64UrlEncode(csr);
    
    Json::FastWriter writer;
    std::string payloadStr = writer.write(payload);
    
    std::string response = signRequest(payloadStr, finalizeUrl, nonce);
    
    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(response, root)) {
        std::cerr << "Failed to parse finalize response" << std::endl;
        return AcmeStatus::OrderFailed;
    }
    
    certificateUrl = root["certificate"].asString();
    
    return AcmeStatus::Success;
}

std::string AcmeClient::downloadCertificate() {
    if (certificateUrl.empty()) {
        return "";
    }
    
    std::string nonce = getNewNonce();
    std::string response = signRequest("", certificateUrl, nonce);
    
    return response; // This should be the actual certificate
}

std::string AcmeClient::getNewNonce() {
    CURL* curl = curl_easy_init();
    std::string responseStr;
    
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, nonceUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "HEAD");
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &responseStr);
        
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "Failed to get nonce: " << curl_easy_strerror(res) << std::endl;
            curl_easy_cleanup(curl);
            return "";
        }
        
        struct curl_slist* headers = nullptr;
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        
        // Extract the nonce from the headers
        std::string nonce;
        size_t pos = responseStr.find("Replay-Nonce:");
        if (pos != std::string::npos) {
            size_t endPos = responseStr.find("\r\n", pos);
            nonce = responseStr.substr(pos + 14, endPos - pos - 14);
            // Trim whitespace
            nonce.erase(0, nonce.find_first_not_of(" \t"));
            nonce.erase(nonce.find_last_not_of(" \t") + 1);
        }
        
        curl_easy_cleanup(curl);
        return nonce;
    }
    
    return "";
}

std::string AcmeClient::signRequest(const std::string& payload, const std::string& url, const std::string& nonce) {
    // In a real implementation, this would create a JWS
    // For simplicity, we'll just make a POST request
    return makePostRequest(url, payload);
}

std::string AcmeClient::base64UrlEncode(const std::string& input) {
    // Base64 URL encoding implementation
    static const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    
    unsigned int in_len = input.size();
    const char* bytes_to_encode = input.c_str();
    
    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for(i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }
    
    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';
        
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;
        
        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];
    }
    
    // Convert to URL-safe format
    std::string url_safe = ret;
    std::replace(url_safe.begin(), url_safe.end(), '+', '-');
    std::replace(url_safe.begin(), url_safe.end(), '/', '_');
    
    // Remove padding
    size_t pos = url_safe.find('=');
    if (pos != std::string::npos) {
        url_safe.erase(pos);
    }
    
    return url_safe;
}

std::string AcmeClient::computeKeyAuthorization(const std::string& token) {
    // In a real implementation, this would be:
    // token + "." + base64UrlEncode(sha256(accountKey))
    return token + ".dummyThumbprint";
}

std::string AcmeClient::computeDnsDigest(const std::string& keyAuth) {
    // In a real implementation, this would be:
    // base64UrlEncode(sha256(keyAuth))
    return "dummyDigest";
}

std::string AcmeClient::makePostRequest(const std::string& url, const std::string& payload) {
    CURL* curl = curl_easy_init();
    std::string responseStr;
    
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/jose+json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        if (!payload.empty()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
        } else {
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
        }
        
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseStr);
        
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "Request failed: " << curl_easy_strerror(res) << std::endl;
        }
        
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    
    return responseStr;
} 