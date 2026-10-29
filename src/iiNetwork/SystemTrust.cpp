#include "SystemTrustInternal.h"
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#if defined(__APPLE__)
#include <Security/Security.h>
#include <TargetConditionals.h>
#elif defined(_WIN32)
#include <windows.h>
#include <wincrypt.h>
#endif
#include <filesystem>
#include <memory>
#include <vector>

namespace ii::network::detail {
namespace {
#if defined(__APPLE__) && TARGET_OS_IOS
struct ReleaseCF final { void operator()(const void* value) const { if(value) CFRelease(value); } };
template<class T> using CF = std::unique_ptr<std::remove_pointer_t<T>, ReleaseCF>;
bool native_verification(X509_STORE_CTX* store) {
    auto* leaf = X509_STORE_CTX_get0_cert(store);
    if (!leaf) return false;
    CF<CFMutableArrayRef> certificates(CFArrayCreateMutable(nullptr, 0, &kCFTypeArrayCallBacks));
    if (!certificates) return false;
    const auto add = [&](X509* certificate) {
        const int count = i2d_X509(certificate, nullptr);
        if (count <= 0 || count > 16*1024*1024) return false;
        std::vector<unsigned char> bytes(static_cast<std::size_t>(count));
        auto* cursor = bytes.data();
        if (i2d_X509(certificate, &cursor) != count) return false;
        CF<CFDataRef> data(CFDataCreate(nullptr, bytes.data(), count));
        CF<SecCertificateRef> native(data ? SecCertificateCreateWithData(nullptr, data.get()) : nullptr);
        if (!native) return false;
        CFArrayAppendValue(certificates.get(), native.get());
        return true;
    };
    if (!add(leaf)) return false;
    auto* chain = X509_STORE_CTX_get0_untrusted(store);
    const int count = chain ? sk_X509_num(chain) : 0;
    if (count > 100) return false;
    for (int i = 0; i < count; ++i) {
        auto* certificate = sk_X509_value(chain, i);
        if (X509_cmp(certificate, leaf) && !add(certificate)) return false;
    }
    auto* parameters = X509_STORE_CTX_get0_param(store);
    const auto* hostname = X509_VERIFY_PARAM_get0_host(parameters, 0);
    CF<CFStringRef> name(hostname ? CFStringCreateWithCString(nullptr, hostname, kCFStringEncodingUTF8) : nullptr);
    auto* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx()));
    CF<SecPolicyRef> policy(SecPolicyCreateSSL(!ssl || !SSL_is_server(ssl), name.get()));
    SecTrustRef raw = nullptr;
    if (!policy || SecTrustCreateWithCertificates(certificates.get(), policy.get(), &raw) != errSecSuccess) return false;
    CF<SecTrustRef> trust(raw);
    // Never perform a hidden synchronous network fetch on the Core event loop.
    if (SecTrustSetNetworkFetchAllowed(trust.get(), false) != errSecSuccess ||
        !SecTrustEvaluateWithError(trust.get(), nullptr)) return false;
    const int depth = X509_VERIFY_PARAM_get_depth(parameters);
    if (depth >= 0 && SecTrustGetCertificateCount(trust.get()) > depth + 2) return false;
    if (hostname && X509_check_host(leaf, hostname, 0, X509_VERIFY_PARAM_get_hostflags(parameters), nullptr) != 1) return false;
    std::unique_ptr<char, decltype([](char* p){OPENSSL_free(p);})> ip(X509_VERIFY_PARAM_get1_ip_asc(parameters));
    if (ip && X509_check_ip_asc(leaf, ip.get(), 0) != 1) return false;
    return true;
}
int verify_native(X509_STORE_CTX* store, void*) noexcept {
    try {
        const bool valid = native_verification(store);
        X509_STORE_CTX_set_error(store, valid ? X509_V_OK : X509_V_ERR_CERT_UNTRUSTED);
        return valid ? 1 : 0;
    } catch (...) {
        X509_STORE_CTX_set_error(store, X509_V_ERR_OUT_OF_MEM);
        return 0;
    }
}
#endif
bool append(X509_STORE* store,const unsigned char* bytes,long size){
    auto* certificate=d2i_X509(nullptr,&bytes,size);if(!certificate){ERR_clear_error();return false;}
    const auto status=X509_STORE_add_cert(store,certificate);X509_free(certificate);
    if(status==1)return true;
    const auto duplicate=ERR_GET_REASON(ERR_peek_last_error())==X509_R_CERT_ALREADY_IN_HASH_TABLE;ERR_clear_error();return duplicate;
}
}
bool load_system_trust(SSL_CTX* context){
    if(!context)return false;
#if defined(__APPLE__) && TARGET_OS_IOS
    SSL_CTX_set_cert_verify_callback(context, verify_native, nullptr);
    return true;
#elif defined(__APPLE__)
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
