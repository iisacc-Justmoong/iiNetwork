#pragma once
#include <openssl/ssl.h>
namespace ii::network::detail {
// Populate OpenSSL's verifier from the OS anchors, independently of the SDK's
// build/install prefix. Explicit policy CA files/pins bypass this default.
bool load_system_trust(SSL_CTX*);
}
