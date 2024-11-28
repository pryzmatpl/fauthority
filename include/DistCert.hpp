#ifndef DIST_CERT
#define DIST_CERT

#include "P2PNode.hpp"
#include "DHT.hpp"

class DistCert {
    public:
        bool signLocal(FNode &signer);
        bool isValid(DHT &peerNet);
};

#endif // CERT_DIST