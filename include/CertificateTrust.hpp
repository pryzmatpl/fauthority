class CertificateTrust {
public:
    static bool installInSystemStore(const Certificate& cert);
    static bool verifyAgainstSystemStore(const Certificate& cert);
    static bool exportForWebServer(const Certificate& cert, const std::string& path);
}; 