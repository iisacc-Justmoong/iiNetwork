#include <iiNetwork/Tls.h>
#include "../src/Security/SystemTrustInternal.h"
#include <cstdlib>
#include <iostream>
#ifdef __APPLE__
#include <TargetConditionals.h>
#endif
#define CHECK(x)do{if(!(x)){std::cerr<<__LINE__<<": " #x "\n";std::exit(1);}}while(false)
int main(){
    auto* context=SSL_CTX_new(TLS_method());CHECK(context);CHECK(ii::network::detail::load_system_trust(context));
    const auto count=sk_X509_OBJECT_num(X509_STORE_get0_objects(SSL_CTX_get_cert_store(context)));
#if defined(__APPLE__) && TARGET_OS_IOS
    CHECK(count==0); // iPadOS evaluates the peer chain using SecTrust; no root export API.
#else
    CHECK(count>0);
#endif
    CHECK(ii::network::TlsContext::client());SSL_CTX_free(context);
    CHECK(!ii::network::detail::load_system_trust(nullptr));
    std::cout<<"SYSTEM_TRUST_OK anchors="<<count<<'\n';
}
