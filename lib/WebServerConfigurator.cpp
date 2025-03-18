#include "WebServerConfigurator.hpp"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <sstream>
#include <filesystem>
#include <regex>
#include <sys/stat.h>

WebServerConfigurator::WebServerConfigurator()
    : apacheConfigPath("/etc/apache2"),
      nginxConfigPath("/etc/nginx"),
      lighttpdConfigPath("/etc/lighttpd"),
      iisConfigPath("C:\\inetpub\\wwwroot") {
}

WebServerType WebServerConfigurator::detectWebServer() {
    // Check for Apache
    if (std::system("which apache2 > /dev/null 2>&1") == 0 || 
        std::system("which httpd > /dev/null 2>&1") == 0) {
        return WebServerType::Apache;
    }
    
    // Check for Nginx
    if (std::system("which nginx > /dev/null 2>&1") == 0) {
        return WebServerType::Nginx;
    }
    
    // Check for Lighttpd
    if (std::system("which lighttpd > /dev/null 2>&1") == 0) {
        return WebServerType::LightHttpd;
    }
    
    // Check for IIS (Windows only)
    #ifdef _WIN32
    if (std::system("where /q appcmd.exe") == 0) {
        return WebServerType::IIS;
    }
    #endif
    
    return WebServerType::Unknown;
}

ConfigStatus WebServerConfigurator::installCertificate(
    const Certificate& cert, 
    const std::string& privateKeyPath,
    WebServerType serverType) {
    
    // Auto-detect server type if not specified
    if (serverType == WebServerType::Unknown) {
        serverType = detectWebServer();
        if (serverType == WebServerType::Unknown) {
            lastError = "Could not detect web server type";
            return ConfigStatus::NotSupported;
        }
    }
    
    // Check if private key exists
    if (!fileExists(privateKeyPath)) {
        lastError = "Private key file not found: " + privateKeyPath;
        return ConfigStatus::Failed;
    }
    
    // Install the certificate based on server type
    switch (serverType) {
        case WebServerType::Apache:
            return installCertificateApache(cert, privateKeyPath);
        case WebServerType::Nginx:
            return installCertificateNginx(cert, privateKeyPath);
        case WebServerType::LightHttpd:
            return installCertificateLightHttpd(cert, privateKeyPath);
        case WebServerType::IIS:
            return installCertificateIIS(cert, privateKeyPath);
        default:
            lastError = "Unsupported web server type";
            return ConfigStatus::NotSupported;
    }
}

ConfigStatus WebServerConfigurator::configureHttps(WebServerType serverType) {
    // Auto-detect server type if not specified
    if (serverType == WebServerType::Unknown) {
        serverType = detectWebServer();
        if (serverType == WebServerType::Unknown) {
            lastError = "Could not detect web server type";
            return ConfigStatus::NotSupported;
        }
    }
    
    // Configure HTTPS based on server type
    switch (serverType) {
        case WebServerType::Apache:
            return configureHttpsApache();
        case WebServerType::Nginx:
            return configureHttpsNginx();
        case WebServerType::LightHttpd:
            return configureHttpsLightHttpd();
        case WebServerType::IIS:
            return configureHttpsIIS();
        default:
            lastError = "Unsupported web server type";
            return ConfigStatus::NotSupported;
    }
}

ConfigStatus WebServerConfigurator::enableHttpsRedirect(WebServerType serverType) {
    // Auto-detect server type if not specified
    if (serverType == WebServerType::Unknown) {
        serverType = detectWebServer();
        if (serverType == WebServerType::Unknown) {
            lastError = "Could not detect web server type";
            return ConfigStatus::NotSupported;
        }
    }
    
    // Configure HTTPS redirect based on server type
    switch (serverType) {
        case WebServerType::Apache:
            return enableHttpsRedirectApache();
        case WebServerType::Nginx:
            return enableHttpsRedirectNginx();
        case WebServerType::LightHttpd:
            return enableHttpsRedirectLightHttpd();
        case WebServerType::IIS:
            return enableHttpsRedirectIIS();
        default:
            lastError = "Unsupported web server type";
            return ConfigStatus::NotSupported;
    }
}

// Apache implementations
ConfigStatus WebServerConfigurator::installCertificateApache(
    const Certificate& cert, 
    const std::string& privateKeyPath) {
    
    // Create certificates directory if it doesn't exist
    std::string certsDir = apacheConfigPath + "/ssl";
    if (!createDirectory(certsDir)) {
        lastError = "Failed to create certificates directory: " + certsDir;
        return ConfigStatus::PermissionDenied;
    }
    
    // Extract domain from certificate
    // In a real implementation, this would extract CN from the X509 certificate
    std::string domain = "example.com"; // Placeholder
    
    // Save certificate file
    std::string certPath = certsDir + "/" + domain + ".crt";
    std::ofstream certFile(certPath);
    if (!certFile) {
        lastError = "Failed to create certificate file: " + certPath;
        return ConfigStatus::PermissionDenied;
    }
    certFile << cert.toPEM();
    certFile.close();
    
    // Create symlink to private key if it's not in the expected location
    std::string keyDestPath = certsDir + "/" + domain + ".key";
    if (privateKeyPath != keyDestPath) {
        // Copy the private key
        std::ifstream keySource(privateKeyPath, std::ios::binary);
        std::ofstream keyDest(keyDestPath, std::ios::binary);
        if (!keySource || !keyDest) {
            lastError = "Failed to copy private key";
            return ConfigStatus::PermissionDenied;
        }
        keyDest << keySource.rdbuf();
        keySource.close();
        keyDest.close();
    }
    
    // Ensure proper permissions
    chmod(certPath.c_str(), 0644);
    chmod(keyDestPath.c_str(), 0600);
    
    std::cout << "Installed certificate for Apache: " << domain << std::endl;
    return ConfigStatus::Success;
}

ConfigStatus WebServerConfigurator::configureHttpsApache() {
    // Check if SSL module is enabled
    if (std::system("apache2ctl -M 2>/dev/null | grep -q ssl_module") != 0) {
        // Enable SSL module
        if (std::system("sudo a2enmod ssl") != 0) {
            lastError = "Failed to enable Apache SSL module";
            return ConfigStatus::Failed;
        }
    }
    
    // Create a default SSL configuration
    std::string sitesAvailableDir = apacheConfigPath + "/sites-available";
    std::string sslConfigPath = sitesAvailableDir + "/default-ssl.conf";
    
    if (!fileExists(sslConfigPath)) {
        std::ofstream sslConfig(sslConfigPath);
        if (!sslConfig) {
            lastError = "Failed to create SSL configuration file";
            return ConfigStatus::PermissionDenied;
        }
        
        sslConfig << "<VirtualHost *:443>\n";
        sslConfig << "    ServerAdmin webmaster@localhost\n";
        sslConfig << "    DocumentRoot /var/www/html\n\n";
        sslConfig << "    SSLEngine on\n";
        sslConfig << "    SSLCertificateFile /etc/apache2/ssl/example.com.crt\n";
        sslConfig << "    SSLCertificateKeyFile /etc/apache2/ssl/example.com.key\n\n";
        sslConfig << "    <Directory /var/www/html>\n";
        sslConfig << "        Options Indexes FollowSymLinks\n";
        sslConfig << "        AllowOverride All\n";
        sslConfig << "        Require all granted\n";
        sslConfig << "    </Directory>\n";
        sslConfig << "</VirtualHost>\n";
        
        sslConfig.close();
    }
    
    // Enable the SSL site
    if (std::system("sudo a2ensite default-ssl") != 0) {
        lastError = "Failed to enable SSL site";
        return ConfigStatus::Failed;
    }
    
    // Restart Apache
    if (!restartWebServer(WebServerType::Apache)) {
        lastError = "Failed to restart Apache";
        return ConfigStatus::Failed;
    }
    
    std::cout << "HTTPS configured for Apache" << std::endl;
    return ConfigStatus::Success;
}

ConfigStatus WebServerConfigurator::enableHttpsRedirectApache() {
    // Check if rewrite module is enabled
    if (std::system("apache2ctl -M 2>/dev/null | grep -q rewrite_module") != 0) {
        // Enable rewrite module
        if (std::system("sudo a2enmod rewrite") != 0) {
            lastError = "Failed to enable Apache rewrite module";
            return ConfigStatus::Failed;
        }
    }
    
    // Create or update the default site configuration
    std::string sitesAvailableDir = apacheConfigPath + "/sites-available";
    std::string defaultSitePath = sitesAvailableDir + "/000-default.conf";
    
    // Backup the original file
    if (!backupConfigFile(defaultSitePath)) {
        lastError = "Failed to backup default site configuration";
        return ConfigStatus::Failed;
    }
    
    // Read the existing configuration
    std::ifstream configFile(defaultSitePath);
    if (!configFile) {
        lastError = "Failed to open default site configuration";
        return ConfigStatus::Failed;
    }
    
    std::string configContent((std::istreambuf_iterator<char>(configFile)),
                              std::istreambuf_iterator<char>());
    configFile.close();
    
    // Add rewrite rules if they don't exist
    if (configContent.find("RewriteEngine") == std::string::npos) {
        std::regex virtualHostPattern("<VirtualHost \\*:80>");
        std::string replacement = "<VirtualHost *:80>\n"
                                 "    RewriteEngine On\n"
                                 "    RewriteCond %{HTTPS} off\n"
                                 "    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]";
        
        configContent = std::regex_replace(configContent, virtualHostPattern, replacement);
        
        // Write the updated configuration
        std::ofstream outFile(defaultSitePath);
        if (!outFile) {
            lastError = "Failed to write to default site configuration";
            return ConfigStatus::PermissionDenied;
        }
        
        outFile << configContent;
        outFile.close();
    }
    
    // Restart Apache
    if (!restartWebServer(WebServerType::Apache)) {
        lastError = "Failed to restart Apache";
        return ConfigStatus::Failed;
    }
    
    std::cout << "HTTPS redirect configured for Apache" << std::endl;
    return ConfigStatus::Success;
}

// Nginx implementations
ConfigStatus WebServerConfigurator::installCertificateNginx(
    const Certificate& cert, 
    const std::string& privateKeyPath) {
    
    // Create certificates directory if it doesn't exist
    std::string certsDir = nginxConfigPath + "/ssl";
    if (!createDirectory(certsDir)) {
        lastError = "Failed to create certificates directory: " + certsDir;
        return ConfigStatus::PermissionDenied;
    }
    
    // Extract domain from certificate
    // In a real implementation, this would extract CN from the X509 certificate
    std::string domain = "example.com"; // Placeholder
    
    // Save certificate file
    std::string certPath = certsDir + "/" + domain + ".crt";
    std::ofstream certFile(certPath);
    if (!certFile) {
        lastError = "Failed to create certificate file: " + certPath;
        return ConfigStatus::PermissionDenied;
    }
    certFile << cert.toPEM();
    certFile.close();
    
    // Create symlink to private key if it's not in the expected location
    std::string keyDestPath = certsDir + "/" + domain + ".key";
    if (privateKeyPath != keyDestPath) {
        // Copy the private key
        std::ifstream keySource(privateKeyPath, std::ios::binary);
        std::ofstream keyDest(keyDestPath, std::ios::binary);
        if (!keySource || !keyDest) {
            lastError = "Failed to copy private key";
            return ConfigStatus::PermissionDenied;
        }
        keyDest << keySource.rdbuf();
        keySource.close();
        keyDest.close();
    }
    
    // Ensure proper permissions
    chmod(certPath.c_str(), 0644);
    chmod(keyDestPath.c_str(), 0600);
    
    std::cout << "Installed certificate for Nginx: " << domain << std::endl;
    return ConfigStatus::Success;
}

ConfigStatus WebServerConfigurator::configureHttpsNginx() {
    // Create a default SSL configuration
    std::string sitesAvailableDir = nginxConfigPath + "/sites-available";
    if (!createDirectory(sitesAvailableDir)) {
        lastError = "Failed to create sites-available directory";
        return ConfigStatus::PermissionDenied;
    }
    
    std::string sitesEnabledDir = nginxConfigPath + "/sites-enabled";
    if (!createDirectory(sitesEnabledDir)) {
        lastError = "Failed to create sites-enabled directory";
        return ConfigStatus::PermissionDenied;
    }
    
    std::string sslConfigPath = sitesAvailableDir + "/default-ssl";
    
    if (!fileExists(sslConfigPath)) {
        std::ofstream sslConfig(sslConfigPath);
        if (!sslConfig) {
            lastError = "Failed to create SSL configuration file";
            return ConfigStatus::PermissionDenied;
        }
        
        sslConfig << "server {\n";
        sslConfig << "    listen 443 ssl;\n";
        sslConfig << "    server_name example.com;\n\n";
        sslConfig << "    ssl_certificate " << nginxConfigPath << "/ssl/example.com.crt;\n";
        sslConfig << "    ssl_certificate_key " << nginxConfigPath << "/ssl/example.com.key;\n";
        sslConfig << "    ssl_protocols TLSv1.2 TLSv1.3;\n";
        sslConfig << "    ssl_ciphers HIGH:!aNULL:!MD5;\n\n";
        sslConfig << "    root /var/www/html;\n";
        sslConfig << "    index index.html index.htm;\n\n";
        sslConfig << "    location / {\n";
        sslConfig << "        try_files $uri $uri/ =404;\n";
        sslConfig << "    }\n";
        sslConfig << "}\n";
        
        sslConfig.close();
    }
    
    // Create a symlink in sites-enabled
    std::string symlinkPath = sitesEnabledDir + "/default-ssl";
    if (!fileExists(symlinkPath)) {
        std::string command = "ln -s " + sslConfigPath + " " + symlinkPath;
        if (std::system(command.c_str()) != 0) {
            lastError = "Failed to enable SSL site";
            return ConfigStatus::Failed;
        }
    }
    
    // Make sure the configuration is valid
    if (std::system("nginx -t") != 0) {
        lastError = "Nginx configuration test failed";
        return ConfigStatus::Failed;
    }
    
    // Restart Nginx
    if (!restartWebServer(WebServerType::Nginx)) {
        lastError = "Failed to restart Nginx";
        return ConfigStatus::Failed;
    }
    
    std::cout << "HTTPS configured for Nginx" << std::endl;
    return ConfigStatus::Success;
}

ConfigStatus WebServerConfigurator::enableHttpsRedirectNginx() {
    // Create or update the default site configuration
    std::string sitesAvailableDir = nginxConfigPath + "/sites-available";
    std::string defaultSitePath = sitesAvailableDir + "/default";
    
    // Backup the original file
    if (!backupConfigFile(defaultSitePath)) {
        lastError = "Failed to backup default site configuration";
        return ConfigStatus::Failed;
    }
    
    // Create a new configuration with redirect
    std::ofstream configFile(defaultSitePath);
    if (!configFile) {
        lastError = "Failed to open default site configuration";
        return ConfigStatus::Failed;
    }
    
    configFile << "server {\n";
    configFile << "    listen 80;\n";
    configFile << "    server_name _;\n\n";
    configFile << "    return 301 https://$host$request_uri;\n";
    configFile << "}\n";
    
    configFile.close();
    
    // Make sure the configuration is valid
    if (std::system("nginx -t") != 0) {
        lastError = "Nginx configuration test failed";
        return ConfigStatus::Failed;
    }
    
    // Restart Nginx
    if (!restartWebServer(WebServerType::Nginx)) {
        lastError = "Failed to restart Nginx";
        return ConfigStatus::Failed;
    }
    
    std::cout << "HTTPS redirect configured for Nginx" << std::endl;
    return ConfigStatus::Success;
}

// Lighttpd implementations
ConfigStatus WebServerConfigurator::installCertificateLightHttpd(
    const Certificate& cert, 
    const std::string& privateKeyPath) {
    
    // Create certificates directory if it doesn't exist
    std::string certsDir = lighttpdConfigPath + "/ssl";
    if (!createDirectory(certsDir)) {
        lastError = "Failed to create certificates directory: " + certsDir;
        return ConfigStatus::PermissionDenied;
    }
    
    // Extract domain from certificate
    // In a real implementation, this would extract CN from the X509 certificate
    std::string domain = "example.com"; // Placeholder
    
    // Save certificate file
    std::string certPath = certsDir + "/" + domain + ".pem";
    std::ofstream certFile(certPath);
    if (!certFile) {
        lastError = "Failed to create certificate file: " + certPath;
        return ConfigStatus::PermissionDenied;
    }
    
    // For lighttpd, we need to combine certificate and key in one file
    certFile << cert.toPEM();
    
    // Append the private key
    std::ifstream keyFile(privateKeyPath);
    if (!keyFile) {
        lastError = "Failed to open private key file";
        return ConfigStatus::Failed;
    }
    
    certFile << std::endl;
    certFile << keyFile.rdbuf();
    
    certFile.close();
    keyFile.close();
    
    // Ensure proper permissions
    chmod(certPath.c_str(), 0600);
    
    std::cout << "Installed certificate for Lighttpd: " << domain << std::endl;
    return ConfigStatus::Success;
}

ConfigStatus WebServerConfigurator::configureHttpsLightHttpd() {
    // Check if SSL module is enabled
    std::string modulesConf = lighttpdConfigPath + "/conf-available/10-ssl.conf";
    if (!fileExists(modulesConf)) {
        lastError = "Lighttpd SSL module configuration not found";
        return ConfigStatus::Failed;
    }
    
    // Enable the SSL module
    std::string enableCommand = "lighttpd-enable-mod ssl";
    if (std::system(enableCommand.c_str()) != 0) {
        lastError = "Failed to enable Lighttpd SSL module";
        return ConfigStatus::Failed;
    }
    
    // Update the SSL configuration
    std::string sslConfPath = lighttpdConfigPath + "/conf-enabled/10-ssl.conf";
    
    // Backup the original file
    if (fileExists(sslConfPath) && !backupConfigFile(sslConfPath)) {
        lastError = "Failed to backup SSL configuration";
        return ConfigStatus::Failed;
    }
    
    // Write new SSL configuration
    std::ofstream sslConf(sslConfPath);
    if (!sslConf) {
        lastError = "Failed to create SSL configuration file";
        return ConfigStatus::PermissionDenied;
    }
    
    sslConf << "server.modules += ( \"mod_ssl\" )\n\n";
    sslConf << "# SSL configuration\n";
    sslConf << "$SERVER[\"socket\"] == \":443\" {\n";
    sslConf << "    ssl.engine = \"enable\"\n";
    sslConf << "    ssl.pemfile = \"" << lighttpdConfigPath << "/ssl/example.com.pem\"\n";
    sslConf << "    ssl.cipher-list = \"EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH\"\n";
    sslConf << "    ssl.honor-cipher-order = \"enable\"\n";
    sslConf << "}\n";
    
    sslConf.close();
    
    // Restart Lighttpd
    if (!restartWebServer(WebServerType::LightHttpd)) {
        lastError = "Failed to restart Lighttpd";
        return ConfigStatus::Failed;
    }
    
    std::cout << "HTTPS configured for Lighttpd" << std::endl;
    return ConfigStatus::Success;
}

ConfigStatus WebServerConfigurator::enableHttpsRedirectLightHttpd() {
    // Enable the redirect module
    std::string enableCommand = "lighttpd-enable-mod redirect";
    if (std::system(enableCommand.c_str()) != 0) {
        lastError = "Failed to enable Lighttpd redirect module";
        return ConfigStatus::Failed;
    }
    
    // Update the redirect configuration
    std::string redirectConfPath = lighttpdConfigPath + "/conf-enabled/10-redirect.conf";
    
    // Backup the original file
    if (fileExists(redirectConfPath) && !backupConfigFile(redirectConfPath)) {
        lastError = "Failed to backup redirect configuration";
        return ConfigStatus::Failed;
    }
    
    // Write new redirect configuration
    std::ofstream redirectConf(redirectConfPath);
    if (!redirectConf) {
        lastError = "Failed to create redirect configuration file";
        return ConfigStatus::PermissionDenied;
    }
    
    redirectConf << "server.modules += ( \"mod_redirect\" )\n\n";
    redirectConf << "# Redirect all HTTP traffic to HTTPS\n";
    redirectConf << "$HTTP[\"scheme\"] == \"http\" {\n";
    redirectConf << "    $HTTP[\"host\"] =~ \".*\" {\n";
    redirectConf << "        url.redirect = (\".*\" => \"https://%0$0\")\n";
    redirectConf << "    }\n";
    redirectConf << "}\n";
    
    redirectConf.close();
    
    // Restart Lighttpd
    if (!restartWebServer(WebServerType::LightHttpd)) {
        lastError = "Failed to restart Lighttpd";
        return ConfigStatus::Failed;
    }
    
    std::cout << "HTTPS redirect configured for Lighttpd" << std::endl;
    return ConfigStatus::Success;
}

// IIS implementations (Windows-specific)
ConfigStatus WebServerConfigurator::installCertificateIIS(
    const Certificate& cert, 
    const std::string& privateKeyPath) {
    
    #ifdef _WIN32
    // Create temporary PFX file by combining cert and private key
    std::string tempCertPath = std::tmpnam(nullptr) + std::string(".crt");
    std::string tempPfxPath = std::tmpnam(nullptr) + std::string(".pfx");
    
    // Save certificate to temporary file
    std::ofstream certFile(tempCertPath);
    if (!certFile) {
        lastError = "Failed to create temporary certificate file";
        return ConfigStatus::Failed;
    }
    certFile << cert.toPEM();
    certFile.close();
    
    // Create PFX file
    std::string password = "TemporaryPassword";
    std::string command = "openssl pkcs12 -export -out " + tempPfxPath + 
                         " -inkey " + privateKeyPath + 
                         " -in " + tempCertPath + 
                         " -password pass:" + password;
    
    if (std::system(command.c_str()) != 0) {
        lastError = "Failed to create PFX file";
        std::remove(tempCertPath.c_str());
        return ConfigStatus::Failed;
    }
    
    // Import PFX into Windows certificate store
    command = "certutil -importpfx -p " + password + 
             " -f -norestart -Enterprise " + tempPfxPath;
    
    if (std::system(command.c_str()) != 0) {
        lastError = "Failed to import certificate into Windows store";
        std::remove(tempCertPath.c_str());
        std::remove(tempPfxPath.c_str());
        return ConfigStatus::Failed;
    }
    
    // Clean up temporary files
    std::remove(tempCertPath.c_str());
    std::remove(tempPfxPath.c_str());
    
    std::cout << "Installed certificate for IIS" << std::endl;
    return ConfigStatus::Success;
    
    #else
    lastError = "IIS is only supported on Windows";
    return ConfigStatus::NotSupported;
    #endif
}

ConfigStatus WebServerConfigurator::configureHttpsIIS() {
    #ifdef _WIN32
    // Get certificate thumbprint
    // In a real implementation, this would be extracted from the certificate
    std::string thumbprint = "PLACEHOLDER_THUMBPRINT";
    
    // Create a binding for port 443
    std::string command = "netsh http add sslcert ipport=0.0.0.0:443 " 
                         "certhash=" + thumbprint + 
                         " appid={00112233-4455-6677-8899-AABBCCDDEEFF}";
    
    if (std::system(command.c_str()) != 0) {
        lastError = "Failed to create SSL binding";
        return ConfigStatus::Failed;
    }
    
    // Configure IIS to use the certificate
    command = "appcmd set site /site.name:\"Default Web Site\" "
             "/bindings:[protocol='https',bindingInformation='*:443:']";
    
    if (std::system(command.c_str()) != 0) {
        lastError = "Failed to configure IIS site for HTTPS";
        return ConfigStatus::Failed;
    }
    
    std::cout << "HTTPS configured for IIS" << std::endl;
    return ConfigStatus::Success;
    
    #else
    lastError = "IIS is only supported on Windows";
    return ConfigStatus::NotSupported;
    #endif
}

ConfigStatus WebServerConfigurator::enableHttpsRedirectIIS() {
    #ifdef _WIN32
    // Install URL Rewrite module if not already installed
    if (std::system("where /q urlrewrite.dll") != 0) {
        lastError = "URL Rewrite module not installed. Please install it from: "
                  "https://www.iis.net/downloads/microsoft/url-rewrite";
        return ConfigStatus::Failed;
    }
    
    // Create web.config file in the root directory
    std::string webConfigPath = iisConfigPath + "\\web.config";
    
    // Backup existing web.config if it exists
    if (fileExists(webConfigPath) && !backupConfigFile(webConfigPath)) {
        lastError = "Failed to backup web.config";
        return ConfigStatus::Failed;
    }
    
    // Create or update web.config
    std::ofstream webConfig(webConfigPath);
    if (!webConfig) {
        lastError = "Failed to create web.config";
        return ConfigStatus::PermissionDenied;
    }
    
    webConfig << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    webConfig << "<configuration>\n";
    webConfig << "  <system.webServer>\n";
    webConfig << "    <rewrite>\n";
    webConfig << "      <rules>\n";
    webConfig << "        <rule name=\"HTTP to HTTPS redirect\" stopProcessing=\"true\">\n";
    webConfig << "          <match url=\"(.*)\" />\n";
    webConfig << "          <conditions>\n";
    webConfig << "            <add input=\"{HTTPS}\" pattern=\"off\" ignoreCase=\"true\" />\n";
    webConfig << "          </conditions>\n";
    webConfig << "          <action type=\"Redirect\" url=\"https://{HTTP_HOST}/{R:1}\" redirectType=\"Permanent\" />\n";
    webConfig << "        </rule>\n";
    webConfig << "      </rules>\n";
    webConfig << "    </rewrite>\n";
    webConfig << "  </system.webServer>\n";
    webConfig << "</configuration>\n";
    
    webConfig.close();
    
    // Restart IIS
    if (!restartWebServer(WebServerType::IIS)) {
        lastError = "Failed to restart IIS";
        return ConfigStatus::Failed;
    }
    
    std::cout << "HTTPS redirect configured for IIS" << std::endl;
    return ConfigStatus::Success;
    
    #else
    lastError = "IIS is only supported on Windows";
    return ConfigStatus::NotSupported;
    #endif
}

// Helper methods
bool WebServerConfigurator::restartWebServer(WebServerType serverType) {
    std::string command;
    
    switch (serverType) {
        case WebServerType::Apache:
            command = "sudo systemctl restart apache2";
            break;
        case WebServerType::Nginx:
            command = "sudo systemctl restart nginx";
            break;
        case WebServerType::LightHttpd:
            command = "sudo systemctl restart lighttpd";
            break;
        case WebServerType::IIS:
            #ifdef _WIN32
            command = "iisreset /restart";
            #else
            return false;
            #endif
            break;
        default:
            return false;
    }
    
    return std::system(command.c_str()) == 0;
}

bool WebServerConfigurator::backupConfigFile(const std::string& configFile) {
    if (!fileExists(configFile)) {
        return true; // Nothing to backup
    }
    
    std::string backupFile = configFile + ".bak";
    std::string command = "cp " + configFile + " " + backupFile;
    
    return std::system(command.c_str()) == 0;
}

std::string WebServerConfigurator::getDefaultConfigPath(WebServerType serverType) {
    switch (serverType) {
        case WebServerType::Apache:
            return apacheConfigPath;
        case WebServerType::Nginx:
            return nginxConfigPath;
        case WebServerType::LightHttpd:
            return lighttpdConfigPath;
        case WebServerType::IIS:
            return iisConfigPath;
        default:
            return "";
    }
}

bool WebServerConfigurator::fileExists(const std::string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

bool WebServerConfigurator::createDirectory(const std::string& path) {
    if (fileExists(path)) {
        return true;
    }
    
    return std::system(("mkdir -p " + path).c_str()) == 0;
} 