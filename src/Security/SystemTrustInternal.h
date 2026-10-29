#pragma once
#include <openssl/ssl.h>
namespace ii::network::detail {
// Configure OS trust independently of the SDK prefix: anchors on desktop,
// Security.framework chain evaluation on iPadOS. Explicit CA files/pins bypass it.
bool load_system_trust(SSL_CTX*);
}
