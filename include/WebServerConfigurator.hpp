#ifndef WEB_SERVER_CONFIGURATOR_HPP
#define WEB_SERVER_CONFIGURATOR_HPP

#include <string>
#include <map>
#include <vector>
#include "Certificate.hpp"

enum class WebServerType {
    Apache,
    Nginx,
    LightHttpd,
    IIS,
    Unknown
};

enum class ConfigStatus {
    Success,
    Failed,
    NotSupported,
    PermissionDenied
};

class WebServerConfigurator {
public:
    WebServerConfigurator();
    
    // Detection
    WebServerType detectWebServer();
    
    // Certificate installation
    ConfigStatus installCertificate(const Certificate& cert, 
                                   const std::string& privateKeyPath,
                                   WebServerType serverType = WebServerType::Unknown);
    
    // HTTPS configuration
    ConfigStatus configureHttps(WebServerType serverType = WebServerType::Unknown);
    ConfigStatus enableHttpsRedirect(WebServerType serverType = WebServerType::Unknown);
    
    // Set custom paths
    void setApacheConfigPath(const std::string& path) { apacheConfigPath = path; }
    void setNginxConfigPath(const std::string& path) { nginxConfigPath = path; }
    void setLightHttpdConfigPath(const std::string& path) { lighttpdConfigPath = path; }
    void setIISConfigPath(const std::string& path) { iisConfigPath = path; }
    
    std::string getLastError() const { return lastError; }
    
private:
    std::string apacheConfigPath;
    std::string nginxConfigPath;
    std::string lighttpdConfigPath;
    std::string iisConfigPath;
    std::string lastError;
    
    // Server-specific implementations
    ConfigStatus installCertificateApache(const Certificate& cert, const std::string& privateKeyPath);
    ConfigStatus installCertificateNginx(const Certificate& cert, const std::string& privateKeyPath);
    ConfigStatus installCertificateLightHttpd(const Certificate& cert, const std::string& privateKeyPath);
    ConfigStatus installCertificateIIS(const Certificate& cert, const std::string& privateKeyPath);
    
    ConfigStatus configureHttpsApache();
    ConfigStatus configureHttpsNginx();
    ConfigStatus configureHttpsLightHttpd();
    ConfigStatus configureHttpsIIS();
    
    ConfigStatus enableHttpsRedirectApache();
    ConfigStatus enableHttpsRedirectNginx();
    ConfigStatus enableHttpsRedirectLightHttpd();
    ConfigStatus enableHttpsRedirectIIS();
    
    // Helper methods
    bool restartWebServer(WebServerType serverType);
    bool backupConfigFile(const std::string& configFile);
    std::string getDefaultConfigPath(WebServerType serverType);
    bool fileExists(const std::string& path);
    bool createDirectory(const std::string& path);
};

#endif // WEB_SERVER_CONFIGURATOR_HPP 