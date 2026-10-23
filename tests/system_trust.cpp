#include <iiNetwork/Tls.h>
#include <iiNetwork/SystemTrustInternal.h>
#include <cstdlib>
#include <iostream>
#define CHECK(x)do{if(!(x)){std::cerr<<__LINE__<<": " #x "\n";std::exit(1);}}while(false)
int main(){
    auto* context=SSL_CTX_new(TLS_method());CHECK(context);CHECK(ii::network::detail::load_system_trust(context));
    const auto count=sk_X509_OBJECT_num(X509_STORE_get0_objects(SSL_CTX_get_cert_store(context)));CHECK(count>0);
    CHECK(ii::network::TlsContext::client());SSL_CTX_free(context);
    CHECK(!ii::network::detail::load_system_trust(nullptr));
    std::cout<<"SYSTEM_TRUST_OK anchors="<<count<<'\n';
}
