#include "SystemTrustInternal.h"
#include <openssl/err.h>
#include <openssl/x509.h>
#if defined(__APPLE__)
#include <Security/Security.h>
#elif defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#endif
#include <filesystem>

namespace ii::network::detail {
namespace {
bool append(X509_STORE* store,const unsigned char* bytes,long size){
    auto* certificate=d2i_X509(nullptr,&bytes,size);if(!certificate){ERR_clear_error();return false;}
    const auto status=X509_STORE_add_cert(store,certificate);X509_free(certificate);
    if(status==1)return true;
    const auto duplicate=ERR_GET_REASON(ERR_peek_last_error())==X509_R_CERT_ALREADY_IN_HASH_TABLE;ERR_clear_error();return duplicate;
}
}
bool load_system_trust(SSL_CTX* context){
    if(!context)return false;
#if defined(__APPLE__)
    CFArrayRef anchors=nullptr;if(SecTrustCopyAnchorCertificates(&anchors)!=errSecSuccess||!anchors)return false;
    std::size_t loaded=0;auto* store=SSL_CTX_get_cert_store(context);
    for(CFIndex i=0;i<CFArrayGetCount(anchors);++i){auto certificate=static_cast<SecCertificateRef>(const_cast<void*>(CFArrayGetValueAtIndex(anchors,i)));auto data=SecCertificateCopyData(certificate);
        if(data){const auto size=CFDataGetLength(data);if(size>0&&size<=16*1024*1024&&append(store,CFDataGetBytePtr(data),long(size)))++loaded;CFRelease(data);}}
    CFRelease(anchors);return loaded!=0;
#elif defined(_WIN32)
    auto store=CertOpenSystemStoreW(0,L"ROOT");if(!store)return false;
    PCCERT_CONTEXT certificate=nullptr;std::size_t loaded=0;
    while((certificate=CertEnumCertificatesInStore(store,certificate)))if(certificate->cbCertEncoded<=16*1024*1024&&append(SSL_CTX_get_cert_store(context),certificate->pbCertEncoded,long(certificate->cbCertEncoded)))++loaded;
    CertCloseStore(store,0);return loaded!=0;
#else
    // Distribution-managed trust remains available after relocating a static
    // OpenSSL kit whose compiled default path points at its staging prefix.
    for(const auto* path:{"/etc/ssl/certs/ca-certificates.crt","/etc/pki/tls/certs/ca-bundle.crt","/etc/ssl/cert.pem"}){
        std::error_code error;if(!std::filesystem::is_regular_file(path,error))continue;
        if(SSL_CTX_load_verify_file(context,path)==1)return true;ERR_clear_error();
    }
    return SSL_CTX_set_default_verify_paths(context)==1;
#endif
}
}
